<?php

use \Leo\Middlewares\RemoteIp;
use \Leo\Fixtures\DummyRequestHandler;
use \PHPUnit\Framework\TestCase;
use \GuzzleHttp\Psr7;

/**
 * @testdox Leo\Middlewares\RemoteIp
 */
class RemoteIpTest extends TestCase
{
	private const HEADER = 'X-Forwarded-For';

	private $handler;

	public function setUp():void
	{
		$this->handler = new DummyRequestHandler();
	}

	public function testFailOnEmptyHeader():void
	{
		$this->expectException(UnexpectedValueException::class);
		$this->expectExceptionMessage('Remote IP header could not be empty');

		new RemoteIp('');
	}

	public function testSingleAddress():void
	{
		$request = new Psr7\ServerRequest(
			'GET', // HTTP method
			'/', // URI
			[self::HEADER => '10.0.0.1'], // Request headers
			null, // Request body
			'1.1', // Protocol version
			['REMOTE_ADDR' => '127.0.0.1'] // Server params
		);

		$response = (new RemoteIp(self::HEADER))
			->process($request, $this->handler);

		$this->assertSame(
			'10.0.0.1',
			$this->handler->getRequest()->getAttribute('REMOTE_IP')
		);
	}

	public function testMultipleAddresses():void
	{
		$request = new Psr7\ServerRequest(
			'GET', // HTTP method
			'/', // URI
			[self::HEADER => '10.0.0.1, 10.0.0.4, 10.0.0.11'], // Request headers
			null, // Request body
			'1.1', // Protocol version
			['REMOTE_ADDR' => '127.0.0.1'] // Server params
		);

		$response = (new RemoteIp(self::HEADER))
			->process($request, $this->handler);

		$this->assertSame(
			'10.0.0.11',
			$this->handler->getRequest()->getAttribute('REMOTE_IP')
		);
	}

	public function testNotPresentingAddress():void
	{
		$request = new Psr7\ServerRequest(
			'GET', // HTTP method
			'/', // URI
			[], // Request headers
			null, // Request body
			'1.1', // Protocol version
			['REMOTE_ADDR' => '127.0.0.1'] // Server params
		);

		$response = (new RemoteIp(self::HEADER))
			->process($request, $this->handler);

		$this->assertSame(
			'127.0.0.1',
			$this->handler->getRequest()->getAttribute('REMOTE_IP')
		);
	}

	public function testTrustedIp():void
	{
		$request = new Psr7\ServerRequest(
			'GET', // HTTP method
			'/', // URI
			[self::HEADER => '10.0.0.1'], // Request headers
			null, // Request body
			'1.1', // Protocol version
			['REMOTE_ADDR' => '127.0.0.1'] // Server params
		);

		$response = (new RemoteIp(self::HEADER, ['127.0.0.1']))
			->process($request, $this->handler);

		$this->assertSame(
			'10.0.0.1',
			$this->handler->getRequest()->getAttribute('REMOTE_IP')
		);
	}

	public function testTrustedCidr():void
	{
		$request = new Psr7\ServerRequest(
			'GET', // HTTP method
			'/', // URI
			[self::HEADER => '10.0.0.1'], // Request headers
			null, // Request body
			'1.1', // Protocol version
			['REMOTE_ADDR' => '192.168.1.100'] // Server params
		);

		$response = (new RemoteIp(self::HEADER, ['192.168.1.0/24']))
			->process($request, $this->handler);

		$this->assertSame(
			'10.0.0.1',
			$this->handler->getRequest()->getAttribute('REMOTE_IP')
		);
	}

	public function testUntrustedHost():void
	{
		$request = new Psr7\ServerRequest(
			'GET', // HTTP method
			'/', // URI
			[self::HEADER => '10.0.0.1'], // Request headers
			null, // Request body
			'1.1', // Protocol version
			['REMOTE_ADDR' => '192.168.1.100'] // Server params
		);

		$response = (new RemoteIp(self::HEADER, ['192.168.1.1', '192.168.0.0/24']))
			->process($request, $this->handler);

		$this->assertSame(
			'192.168.1.100',
			$this->handler->getRequest()->getAttribute('REMOTE_IP')
		);
	}

	public function testFailOnInvalidHost():void
	{
		$this->expectException(UnexpectedValueException::class);
		$this->expectExceptionMessageMatches('/.*?not a valid IP address or CIDR/');

		new RemoteIp(self::HEADER, ['nonsense']);
	}

	public function testFailOnMalformedCidrWithoutSingleSlash():void
	{
		$this->expectException(UnexpectedValueException::class);
		$this->expectExceptionMessageMatches('/.*?not a valid IP address or CIDR/');

		new RemoteIp(self::HEADER, ['127.0.0.0/8/abcd']);
	}

	public function testFailOnMalformedCidrWithInvalidNetwork():void
	{
		$this->expectException(UnexpectedValueException::class);
		$this->expectExceptionMessageMatches('/.*?not a valid IP address or CIDR/');

		new RemoteIp(self::HEADER, ['nonsense/8']);
	}

	public function testFailOnMalformedCidrWithInvalidMask():void
	{
		$this->expectException(UnexpectedValueException::class);
		$this->expectExceptionMessageMatches('/.*?not a valid IP address or CIDR/');

		new RemoteIp(self::HEADER, ['192.168.0.0/128']);
	}
}

?>
