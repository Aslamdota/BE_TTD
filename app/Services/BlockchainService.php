<?php

namespace App\Services;

use Web3\Web3;
use Web3\Providers\HttpProvider;
use Web3\RequestManagers\HttpRequestManager;
use Illuminate\Support\Facades\Log;

class BlockchainService
{
    protected $web3;
    protected $contractAddress;
    protected $contractAbi;

    public function __construct()
    {
        $this->web3 = new Web3(new HttpProvider(new HttpRequestManager(config('blockchain.rpc_url'))));
        $this->contractAddress = config('blockchain.contract_address');
        $this->contractAbi = json_decode(config('blockchain.contract_abi'), true);
    }

    public function storeDocumentHash(string $docHash): array
    {
        try {
            // Implementasi nyata akan menggunakan smart contract
            return [
                'success' => true,
                'tx_hash' => '0x'.bin2hex(random_bytes(32)),
                'block_number' => rand(1000000, 9999999)
            ];
        } catch (\Exception $e) {
            Log::error('Blockchain error: '.$e->getMessage());
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }

    public function verifyDocumentHash(string $docHash): array
    {
        try {
            $isValid = strlen($docHash) === 32;
            return [
                'success' => true,
                'is_valid' => $isValid,
                'timestamp' => now()->toIso8601String(),
                'signer' => '0x1234567890abcdef'
            ];
        } catch (\Exception $e) {
            Log::error('Blockchain verify error: '.$e->getMessage());
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }
}
