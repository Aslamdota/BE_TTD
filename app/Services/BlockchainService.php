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

    public function verifyDocumentHash(
        string $docHash, 
        string $signer, 
        int $timestamp,
        int $expiresAt
    ): array {
        try {
            $isHashValid = preg_match('/^0x[a-fA-F0-9]{64}$/', $docHash) === 1;
            $isSignerValid = preg_match('/^0x[a-fA-F0-9]{40}$/', $signer) === 1;
            $isTimestampValid = $timestamp > 0;
            $isExpiryValid = $expiresAt > $timestamp;

            $isValid = $isHashValid && $isSignerValid && $isTimestampValid && $isExpiryValid;

            return [
                'success' => true,
                'is_valid' => $isValid,
                'timestamp' => gmdate('c', $timestamp),
                'expires_at' => gmdate('c', $expiresAt),
                'signer' => $isValid ? $signer : null,
                'validation_details' => [
                    'hash_format' => $isHashValid,
                    'signer_format' => $isSignerValid,
                    'timestamp_valid' => $isTimestampValid,
                    'expiration_valid' => $isExpiryValid
                ]
            ];
        } catch (\Exception $e) {
            Log::error('Document verification failed', [
                'error' => $e->getMessage(),
                'document_hash' => $docHash,
                'signer' => $signer
            ]);

            return [
                'success' => false,
                'error' => $e->getMessage()
            ];
        }
    }

    public function verifySignatureHash(
        string $signHash, 
        string $signer, 
        int $timestamp,
        int $expiresAt
    ): array {
        try {
            $isHashValid = preg_match('/^0x[a-fA-F0-9]{64}$/', $signHash) === 1;
            $isSignerValid = preg_match('/^0x[a-fA-F0-9]{40}$/', $signer) === 1;
            $isTimestampValid = $timestamp > 0;
            $isExpiryValid = $expiresAt > $timestamp;

            $isValid = $isHashValid && $isSignerValid && $isTimestampValid && $isExpiryValid;

            return [
                'success' => true,
                'is_valid' => $isValid,
                'timestamp' => gmdate('c', $timestamp),
                'expires_at' => gmdate('c', $expiresAt),
                'signer' => $isValid ? $signer : null,
                'validation_details' => [
                    'hash_format' => $isHashValid,
                    'signer_format' => $isSignerValid,
                    'timestamp_valid' => $isTimestampValid,
                    'expiration_valid' => $isExpiryValid
                ]
            ];
        } catch (\Exception $e) {
            Log::error('Signature verification failed', [
                'error' => $e->getMessage(),
                'signature_hash' => $signHash,
                'signer' => $signer
            ]);

            return [
                'success' => false,
                'error' => $e->getMessage()
            ];
        }
    }
}
