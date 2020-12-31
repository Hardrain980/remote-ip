<?php

namespace Leo\Middlewares;

use \Psr\Http\Server\MiddlewareInterface;
use \Psr\Http\Server\RequestHandlerInterface;
use \Psr\Http\Message\ServerRequestInterface;
use \Psr\Http\Message\ResponseInterface;

class RemoteIp implements MiddlewareInterface
{
	/**
	 * @var string Request header passing remote ip
	 */
	private string $remote_ip_header;

	/**
	 * @var array<string> Trusted hosts
	 * Only set remote ip from trusted reverse proxy hosts,
	 * trust any host if this array is empty.
	 */
	private array $trusted_hosts;

	public function __construct(
		string $remote_ip_header = 'X-Forwarded-For',
		array $trusted_hosts = []
	)
	{
		if (!$remote_ip_header)
			throw new \UnexpectedValueException('Remote IP header could not be empty');

		$this->remote_ip_header = $remote_ip_header;
		$this->trusted_hosts = [];

		// Check if trusted_hosts are valid IP or CIDR,
		// save with type prefix if valid,
		// emit exception otherwise.
		foreach ($trusted_hosts as $th) {
			if (filter_var($th, FILTER_VALIDATE_IP) !== false)
				$this->trusted_hosts[] = "ip:{$th}";
			elseif ($this->isValidCidr($th))
				$this->trusted_hosts[] = "cidr:{$th}";
			else
				throw new \UnexpectedValueException("\"{$th}\" is not a valid IP address or CIDR");
		}
	}

	public function process(
		ServerRequestInterface $request,
		RequestHandlerInterface $handler
	):ResponseInterface
	{
		// If host is trusted and remote IP header is present,
		// parse remote ip.
		if (
			($raw = $request->getHeaderLine($this->remote_ip_header)) && 
			$this->isHostTrusted($request->getServerParams()['REMOTE_ADDR'])
		) {
			$ips = explode(',', $raw);
			$ip = trim($ips[count($ips) - 1]);
		}
		else
			$ip = $request->getServerParams()['REMOTE_ADDR'];

		$request = $request
			->withAttribute('REMOTE_IP', $ip);

		return $handler->handle($request);
	}

	private function isValidCidr(string $cidr_in):bool
	{
		$split = explode('/', $cidr_in);

		// CIDR should be separated by single slash, and consists of 2 parts
		if (count($split) != 2)
			return false;

		// The first part should be a valid IP address
		if (filter_var($split[0], FILTER_VALIDATE_IP) === false)
			return false;

		// The second part, the mask should be an integer between 1 to 32
		if (intval($split[1]) < 1 || intval($split[1]) > 32)
			return false;

		return true;
	}

	private function isIpInCidr(string $ip, string $cidr):bool
	{
		list($network, $network_len) = explode('/', $cidr);

		$shift = 0x20 - intval($network_len);

		return (ip2long($network) >> $shift) == (ip2long($ip) >> $shift);
	}

	private function isHostTrusted(string $ip):bool
	{
		// Trust any host if trusted_hosts is empty.
		if ($this->trusted_hosts == [])
			return true;

		foreach ($this->trusted_hosts as $th) {
			list($type, $value) = explode(':', $th, 2);

			switch ($type) {
				case 'ip':
					if ($value === $ip)
						return true;
					break;

				case 'cidr':
					if ($this->isIpInCidr($ip, $value))
						return true;
					break;
			}
		}

		// if no matching found, return false
		return false;
	}
}

?>
