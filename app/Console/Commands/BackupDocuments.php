<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Storage;

class BackupDocuments extends Command
{
    protected $signature = 'backup:documents';
    protected $description = 'Backup documents to S3';

    public function handle()
    {
        $files = Storage::files('documents');
        foreach ($files as $file) {
            Storage::disk('s3')->put($file, Storage::get($file));
        }
        $this->info('Backup selesai!');
    }
}