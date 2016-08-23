/*
 * Copyright (c) 2014 Wael Chatila / Icegreen Technologies. All Rights Reserved.
 * This software is released under the Apache license 2.0
 * This file has been used and modified.
 * Original file can be found on http://foedus.sourceforge.net
 */
package com.icegreen.greenmail.smtp;

import com.icegreen.greenmail.foedus.util.Workspace;
import com.icegreen.greenmail.server.ProtocolHandler;
import com.icegreen.greenmail.smtp.commands.SmtpCommand;
import com.icegreen.greenmail.smtp.commands.SmtpCommandRegistry;
import com.icegreen.greenmail.util.DummySSLSocketFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.net.Socket;
import java.net.SocketTimeoutException;

class SmtpHandler implements ProtocolHandler, HandshakeCompletedListener {
    private static final Logger log = LoggerFactory.getLogger(SmtpHandler.class);

    // protocol and configuration global stuff
    SmtpCommandRegistry _registry;
    SmtpManager _manager;
    Workspace _workspace;

    // session stuff
    SmtpConnection _conn;
    SmtpState _state;

    // command parsing stuff
    boolean _quitting;
    String _currentLine;
    private Socket _socket;
    /*
     * This is a temporary socket used for STARTTLS.
     * It will replace _socket on successful SSL Handshake.
     * */
    private SSLSocket _sslSocketToExchange;

    public SmtpHandler(SmtpCommandRegistry registry,
                       SmtpManager manager, Workspace workspace, Socket socket) {
        _registry = registry;
        _manager = manager;
        _workspace = workspace;
        _socket = socket;
    }

    private void initConnection() throws IOException {

        _conn = new SmtpConnection(this, _socket);
        _state = new SmtpState(_workspace);
    }

    @Override
    public void run() {
        try {
            initConnection();
            _quitting = false;

            sendGreetings();

            while (!_quitting) {
                handleCommand();
            }

        } catch (SocketTimeoutException ste) {
            _conn.send("421 Service shutting down and closing transmission channel");

        } catch (Exception e) {
            // Closing socket on blocked read
            if (!_quitting) {
                log.error("Unexpected error handling connection, quitting=", e);
                throw new IllegalStateException(e);
            }
        } finally {
            if (null != _state) {
                _state.clearMessage();
            }
        }
    }

    protected void sendGreetings() {
        _conn.send("220 " + _conn.getServerGreetingsName() +
                " GreenMail SMTP Service Ready at port " + _conn.sock.getLocalPort());
    }

    protected void handleCommand()
            throws IOException {
        _currentLine = _conn.receiveLine();

        if (_currentLine == null) {
            close();

            return;
        }


        /*
         * Check for STARTTLS command first. If it is, then handle the SSL Socket exchange separately
         *
         * TODO: What do we in case this is already a SSL Socket
         **/

        if (!handleStartTls()) {

            // eliminate invalid line lengths before parsing
            if (!commandLegalSize()) {

                return;
            }

            String commandName = _currentLine.substring(0, 4).toUpperCase();

            SmtpCommand command = _registry.getCommand(commandName);

            if (command == null) {
                _conn.send("500 Command not recognized");

                return;
            }

            command.execute(_conn, _state, _manager, _currentLine);
        }
    }

    private boolean handleStartTls() {

        if (_currentLine.startsWith("STARTTLS")) {

            //Check for any parameters/extra illegal characters sent
            if (!_currentLine.equals("STARTTLS")) {
                _conn.send("501 Syntax error (no parameters allowed)");
            } else {
                //Attempt setting up a SecureSocket to exchange
                try {
                    _sslSocketToExchange = createSslExchangeSocket();
                    //Listen for handshake completion so we can exchange the sockets
                    _sslSocketToExchange.addHandshakeCompletedListener(SmtpHandler.this);
                    _conn.send("220 Ready to start TLS");
                } catch (IOException e) {
                    //Could not create SSLSocket. Reply with appropriate error
                    _conn.send("454 TLS not available due to temporary reason");
                }
            }
            return true;
        }

        return false;
    }

    private SSLSocket createSslExchangeSocket() throws IOException {

        final SSLSocket sslSocket = (SSLSocket) ((SSLSocketFactory) DummySSLSocketFactory.getDefault()).createSocket(_socket, null, _socket.getPort(), true);
        sslSocket.setUseClientMode(false);
        return sslSocket;
    }

    private boolean commandLegalSize() {
        if (_currentLine.length() < 4) {
            _conn.send("500 Invalid command. Must be 4 characters");

            return false;
        }

        if (_currentLine.length() > 4 &&
                _currentLine.charAt(4) != ' ') {
            _conn.send("500 Invalid command. Must be 4 characters");

            return false;
        }

        if (_currentLine.length() > 1000) {
            _conn.send("500 Command too long.  1000 character maximum.");

            return false;
        }

        return true;
    }

    @Override
    public void close() {
        if (log.isTraceEnabled()) {
            final StringBuilder msg = new StringBuilder("Closing SMTP(s) handler connection");
            if (null != _socket) {
                msg.append(' ').append(_socket.getInetAddress()).append(':')
                        .append(_socket.getPort());
            }
            log.trace(msg.toString());
        }
        _quitting = true;
        try {

            if (_sslSocketToExchange != null && !_sslSocketToExchange.isClosed()) {
                /*
                * At some point, STARTTLS was called, but no SSL negotiation was done.
                * Since the socket was created in autoclose mode, closing this will also
                * close the wrapped socket as well
                **/
                _sslSocketToExchange.removeHandshakeCompletedListener(SmtpHandler.this);
                _sslSocketToExchange.close();
                return;
            }
            if (_socket != null && !_socket.isClosed()) {
                _socket.close();
            }
        } catch (IOException ignored) {
            //empty
        }
    }

    @Override
    public void handshakeCompleted(HandshakeCompletedEvent handshakeCompletedEvent) {
        //Handshake is successful. We can replace the socket with the new socket and reset the state
        _sslSocketToExchange.removeHandshakeCompletedListener(SmtpHandler.this);
        _socket = _sslSocketToExchange;
        //We no longer need this since it's a temporary socket
        _sslSocketToExchange = null;

        //After this, we need to reset all SMTP state
        _state.clearMessage();
        _currentLine = null;

        try {
            initConnection();
        } catch (IOException e) {
            //Can anything else be done here apart from closing the connection?
            close();
        }
    }
}