<?php

class IncomingMessage {

	const MESSAGE_NEW = 1;
	const MESSAGE_FRAGMENTED = 2;
	const MESSAGE_READY = 3;

	/** @var handle The socket handle to the connected user. */
	private $user;

	/** @var array The current message as an array of frames. */
	private $contents;

	/** @var callable The function to call when a message is completely received, or a control frame is received. */
	private $messageHandler;

	/** @var bool Whether or not we are in the middle of a fragmented message. */
	private $handlingPartialMessage = false;

	function __construct($user, callable $messageHandler) {
		$this->user = $user;
		$this->contents = array();
		$this->messageHandler = $messageHandler;
	}

	// Rules for assembling messages:
	// * An unfragmented message consists of a single frame with the FIN bit set and the opcode other than 0.
	// * Fragmented messages start with a fragment with an opcode other than 0 and the FIN bit clear.
	// * Intermediate message fragments have an opcode of 0 and the FIN bit clear.
	// * Final fragments have on opcode of 0 and the FIN bit set.
	// * Control frames MAY be injected in the middle of a fragmented message.
	// * Control frames MUST NOT be fragmented.
	// * Message fragments MUST be delivered in the order sent by the sender. (TCP ensures this.)
	// * Messages MUST NOT be interleaved without a pre-negotiated extension. (This implementation does not provide such an extension.)
	// * The server MUST handle control frames immediately, even while in the middle of a fragmented message.
	// * Fragments may be of any size.

	// Assumptions in this system:
	// A connection and a user are the same thing.
	// This object expects the TCP buffer which, due to Nagle's Algorithm, may contain multiple messages.

	// Concerns:
	// Memory DOS -- A malicious user sends a fragmented message [full of garbage?].  Each fragment is below the max
	//     individual frame size, so does not get closed immediately... however, attacker does not send a FIN fragment,
	//     keeping the fragmented message in memory, either continually adding garbage or opening new connections with
	//     similar garbage fragmented messages until available memory is exhausted.
	//     Mitigation: Max fragmented message size (configurable by end developer).  Clear buffer and close connection
	//     if we reach this point.  Stale fragmented messages with global max fragmented buffer limit: If we are passing
	//     a global limit on the size of our buffered fragments, then clear buffer and close connection on the oldest
	//     fragmented messages, where oldest is least recently updated, until we are back below our global limit.
	//     Compatibility: If not set, assume a safe but secure size, but make it clear in config examples that the
	//     option is available and expected.  (val <= 0 means unlimited, as well...  example: buffsize = -1,
	//     buffsize = 0, etc. all mean unlimited; buffsize = 1024 means 1 kilobyte, buffsize = 1k means 1 kilobyte,
	//     buffsize = 1m means 1 megabyte which is 1,048,576 bytes, etc. 1k == 1kb, 1m == 1mb, etc.
	//     Must close the connection in cases where a fragmented message exceeds a limit and triggers a buffer clear,
	//     in order to allow client scripts to recover gracefully if they are designed to.  Status code 1011 seems to
	//     be the most appropriate.  (Maybe we could ask for a 3xxx code from IANA?)
	//     Also should log cases where a buffer is cleared, in case the server is simply getting overloaded and the
	//     developers need to increase thresholds.
	//     Alternative mitigation: If a fragmented message gets too large, swap to disk and set up another sane, larger
	//     limit to the size of swapped data, with cleanup routines.  I.e., if the PID of the server goes away, it's
	//     safe to remove stored fragmented messages, or if a fragmented message sticks around for a few hours, clean
	//     it up, and the server itself should most certainly remove the message once it's consumed or the connection
	//     has gone away.
	//     Well behaved clients should be sending each fragment as quickly as possible, and with sane sizes (with the
	//     definition of sanity being decided by the developer), so closing overly large messages and closing overly old
	//     messages should impact well behaved clients as little as possible.  Still, be descriptive in the close error
	//     message and in the logs to help developers in case they do run into this issue.

	/**
	 * @param $tcpPacket string The payload of the TCP packet as it comes off the network stack.
	 */
	public function receiveFrame($tcpPacket)
	{
		try
		{
			$frame = new Frame($tcpPacket);
		}
		catch (Exception $e)
		{
			$disconnectMessage = new OutgoingMessage();
			$disconnectMessage->setType(OutgoingMessage::ControlFrame);
		}


	}

	public function getContents()
	{

	}

	public function getFrames()
	{

	}
}

class OutgoingMessage {
	private $recipients;

	function __construct($recipients = array())
	{

	}

}

class Frame {
	private $buffer;
	private $finIsSet = false;
	private $opcode;
	private $maskIsSet = false;
	private $payloadLength;
	private $maskKey;
	private $rsv1;
	private $rsv2;
	private $rsv3;
	private $payload;
	private $overflow;

	function __construct($buffer) {
		$this->buffer = $buffer;
		$payloadOffset = 1; // Always will be more, because the mask bit will always be set, but we always start at the minimum.
		                    // Also, it's zero based.

		// First byte: fin{1}, rsv1{1}, rsv2{1}, rsv3{1}, opcode{4}
		$firstByte = decbin(chr($buffer[0]));
		$bit = array_shift($firstByte);
		if ($bit === '1') {
			$this->finIsSet = true;
		}

		$this->rsv1 = array_shift($firstByte);
		$this->rsv2 = array_shift($firstByte);
		$this->rsv3 = array_shift($firstByte);

		$this->opcode = bindec($firstByte);

		// Second byte: mask{1}, length{7}
		$secondByte = decbin(chr($buffer[1]));
		$bit = array_shift($secondByte);
		if ($bit === '1') { // Should always be true, because the mask should always be set.
			$this->maskIsSet = true;
			$payloadOffset += 4;
		}
		$this->payloadLength = bindec($secondByte);
		if ($this->payloadLength === 126) {
			// Note the bitwise OR, not logical OR.
			$this->payloadlength = ord($buffer[2]) << 8 | ord($buffer[3]);
			$payloadOffset += 2;
		} elseif ($this->payloadLength === 127) {
			$payloadOffset += 8;

			$this->payloadLength = ord($buffer[4]) << 56
								 | ord($buffer[3]) << 48
								 | ord($buffer[4]) << 40
								 | ord($buffer[5]) << 32
								 | ord($buffer[6]) << 24
								 | ord($buffer[7]) << 16
								 | ord($buffer[8]) << 8
								 | ord($buffer[9]);

			// Max size is 00 00 00 00 7F FF FF FF, or one byte less than 2GiB, due to PHP's string length limit.
			//
			if ($this->payloadLength > (2147483647 - $payloadOffset)) {
				// Note: We could have an array of strings, each up to 2GiB long... but we won't.  Not in core, at least.
				// Mainly because we get and read the whole frame atomically for right now.
				throw new Exception('Received message too large. Hard limit of 2GB -- PHP itself can not handle larger messages.');
			}
		}

		if ($this->maskIsSet) // Should always be true...
		{
			$this->maskKey = char($buffer[$payloadOffset - 4]) . char($buffer[$payloadOffset - 3]) . char($buffer[$payloadOffset - 2]) . char($buffer[$payloadOffset - 1]);

			$this->payload = substr($buffer, $payloadOffset, $this->payloadLength);
			// Tight loops are fun, aren't they?
			for ($i = 0; $i < $this->payloadLength; $i++) {
				$this->payload[$i] = $this->payload[$i] ^ $this->maskKey[$i % 4];
			}

			$effectiveMask = "";

			while (strlen($effectiveMask) < $this->payloadLength) {
				$effectiveMask .= $this->maskKey;
			}
			while (strlen($effectiveMask) > $this->payloadLength) {
				$effectiveMask = substr($effectiveMask,0,-1);
			}
			$this->payload = $effectiveMask ^ $this->payload;
		}
	}
}