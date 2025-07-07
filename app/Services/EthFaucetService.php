<?php

namespace App\Services;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use kornrunner\Keccak;
use Elliptic\EC;
use Web3p\EthereumTx\Transaction;

class EthFaucetService
{
    protected $rpc;
    protected $privateKey;
    protected $fromAddress;

    public function __construct()
    {
        $this->rpc = config('app.sepolia_rpc');
        $this->privateKey = config('app.faucet_private_key');
        $this->fromAddress = config('app.faucet_address');
    }

    public function sendEth($toAddress, $amountEth = '0.005')
    {
        $nonceResponse = Http::post($this->rpc, [
            'jsonrpc' => '2.0',
            'method' => 'eth_getTransactionCount',
            'params' => [$this->fromAddress, 'pending'],
            'id' => 1,
        ]);

        if (!isset($nonceResponse['result'])) {
            throw new \Exception('Gagal mendapatkan nonce');
        }

        $nonce = hexdec($nonceResponse['result']);

        $txData = [
            'nonce' => '0x' . dechex($nonce),
            'gasPrice' => '0x' . dechex(10 * 1e9),
            'gas' => '0x5208',
            'to' => $toAddress,
            'value' => '0x' . dechex((float)$amountEth * 1e18),
            'chainId' => 11155111,
        ];

        $transaction = new Transaction($txData);
        $signed = '0x' . $transaction->sign($this->privateKey);

        $sendTx = Http::post($this->rpc, [
            'jsonrpc' => '2.0',
            'method' => 'eth_sendRawTransaction',
            'params' => [$signed],
            'id' => 2,
        ]);

        if (isset($sendTx['error'])) {
            $message = $sendTx['error']['message'];

            Log::error('Gagal kirim Faucet', [
                'nonce' => $nonce,
                'message' => $message,
            ]);

            throw new \Exception($message);
        }

        return $sendTx['result'];
    }

}
