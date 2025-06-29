<?php

namespace App\Notifications;
use Illuminate\Notifications\Notification;
use Illuminate\Notifications\Messages\MailMessage;

class DocumentSigned extends Notification
{
    public function via($notifiable) { return ['mail']; }
    public function toMail($notifiable)
    {
        return (new MailMessage)
            ->subject('Dokumen Ditandatangani')
            ->line('Dokumen Anda telah ditandatangani.')
            ->action('Lihat Dokumen', url('/documents'));
    }
}
