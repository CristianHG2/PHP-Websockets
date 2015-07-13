<?php

class WebSocketUser {

  public $socket;
  public $id;
  public $headers = array();
  public $handshake = false;

  public $handlingPartialPacket = false;
  public $partialBuffer = "";

  public $sendingContinuous = false;
  public $partialMessage = "";
  
  public $hasSentClose = false;

  private $messageQueue;

  function __construct($id, $socket) {
    $this->messageQueue = new IncomingMessageQueue($this, array($this, 'handleMessage'));
    $this->id = $id;
    $this->socket = $socket;
  }

  public function handleMessage($message) {

  }

  public function receiveMessage($buffer) {
    $this->messageQueue->receiveFrame($buffer);
  }
}