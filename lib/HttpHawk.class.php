<?php

	/**
	* Http Hawk Request class
	* @description Make a http request with optional HAWK authentication.
	* @author Rob Huzzey<robert.huzzey@holidayextras.com>
	**/

	class HttpHawk {

		private $_auth = null;
		private $_server = null;
		private $_port = '80';
		private $_protocol = 'http';

		private function parseHeader( $headerString ) {
			
			// Split lines
			$headerLines = explode( PHP_EOL, $headerString );
			
			// We want to structure the headers response as key/value pairs
			$headers = array();
			
			// Split each line to key / value
			foreach( $headerLines as $entry ) {
				$pos = strpos( $entry, ':' );
				$key = trim( substr( $entry, 0, $pos ) );
				$value = trim( substr( $entry, ++$pos ) );
				if( $key && $value ) {
					$headers[$key] = $value;
				}
			}
			
			return $headers;
		}
		
		private function parseBody( $bodyString ) {
			return json_decode( $bodyString, true );
		}

		public function __construct( $options ) {

			// Override some defaults if they are passed in.
			foreach( array( 'protocol', 'server', 'port', 'auth' ) as $default ) {
				if( isset( $options[ $default ] ) ) {
					$name = "_$default";
					$this->$name = $options[ $default ];
				}
			}
			
			// Make sure we have the required properties
			if( !isset( $this->_server ) ) {
				throw new Exception( "Server required" );
			}

		}

		public function request( $method, $endpoint, $data ) {

			// Build an encoded query of our data for passing in the body / query string based on verb used.
			$data = http_build_query( $data );

			if ( strtoupper( $method ) === 'GET' ) {
				$endpoint = $endpoint .= '?' . $data;
			}
			
			// Init our curl lib
			$ch = curl_init();
			curl_setopt( $ch, CURLOPT_URL, $this->_protocol . '://' . $this->_server .':'. $this->_port .'/'. $endpoint );
			curl_setopt( $ch, CURLOPT_HEADER, 1 );
			curl_setopt( $ch, CURLOPT_FOLLOWLOCATION, true );
			curl_setopt( $ch, CURLOPT_RETURNTRANSFER, true );
			// MUST SET content type. Otherwise request fails.
			curl_setopt( $ch, CURLOPT_HTTPHEADER, array( 'Content-Type: application/json; charset=utf-8' ) );
			
			if( isset( $this->_auth ) ) {
			
				// make sure we are using UTC for all requests or the auth wont pass
				date_default_timezone_set('UTC');
				// try with our server time for the first request
				$hawkTime = time();

				// used for nonce, dynamic for extra security.
				$secondsSinceMidnight = time() - strtotime( 'today' );

				//this is the exact string that Hawk uses for its hmac, if this changes out of sync with hawk we won't authenticate
				//new lines and spaces matter here! don't remove the 3 at the end.
				$hawkData = "hawk.1.header\n" . $hawkTime .  "\n". $secondsSinceMidnight ."\n" . strtoupper( $method ) . "\n/" . $endpoint . "\n".  $this->_server ."\n".  $this->_port ."\n\n\n";
				// hash and encode the string with our secret key
				$hawkMac = base64_encode( hash_hmac( 'sha256', $hawkData, $this->_auth[ 'secretKey' ], true ) );
				// make our auth header string.
				$hawk = 'Hawk id="'. $this->_auth['accessKey'] .'", ts="'. $hawkTime .'", nonce="'. $secondsSinceMidnight .'", mac="'.$hawkMac.'"';
				
				curl_setopt( $ch, CURLOPT_HTTPHEADER, array( 'x-identifier: ' . md5( $hawkTime ) ) );
				curl_setopt( $ch, CURLOPT_HTTPHEADER, array( 'Authorization: ' . $hawk ) ); // hawks authentication
			}

			if ( $method === 'POST' ) {
				curl_setopt( $ch, CURLOPT_POST, true );
				curl_setopt( $ch, CURLOPT_POSTFIELDS, $data );
			} else if ( $method === 'PUT' ) {
				curl_setopt( $ch, CURLOPT_CUSTOMREQUEST, 'PUT' );
				curl_setopt( $ch, CURLOPT_POSTFIELDS, $data );
			} else if ( $method === 'PATCH' ) {
				curl_setopt( $ch, CURLOPT_CUSTOMREQUEST, 'PATCH' );
				curl_setopt( $ch, CURLOPT_POSTFIELDS, $data );
			}

			$reply = curl_exec( $ch );

			// no response
			if ( !$reply ) {
				//curl doesnt throw exception so check for error and throw it if there is one
				throw new Exception( curl_error( $ch ) );
			}

			curl_close( $ch );

			$result = array(
				"header" => null,
				"body" => null
			);
			
			// split out the header and the body
			list( $result['header'], $result['body'] ) = explode( "\r\n\r\n", $reply, 2 );

			// Parse header
			$result['header'] = $this->parseHeader( $result['header'] );
			
			// Parse body
			$result['body'] = $this->parseBody( $result['body'] );

			return $result;
			
		}

	}

?>