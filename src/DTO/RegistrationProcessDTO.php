<?php

namespace App\DTO;

class RegistrationProcessDTO
{
    public string $signature;
    public string $publicId;
    public string $email;
    public string $processId;    

    public static function mapFromArrayRegistration(array $data): self
    {
        $dto = new self();

        $dto->signature = $data['signature'] ?? '';
        $dto->publicId = $data['publicId'] ?? '';
        $dto->email = $data['email'] ?? '';
        $dto->processId = $data['registrationProcessId'] ?? '';

        return $dto;
    }  
    
    public static function mapFromArrayLogin(array $data): self
    {
        $dto = new self();

        $dto->signature = $data['signature'] ?? '';
        $dto->publicId = $data['publicId'] ?? '';
        $dto->email = $data['email'] ?? '';
        $dto->processId = $data['processId'] ?? '';

        return $dto;
    }      

    /**
     * Get the value of signature
     */ 
    public function getSignature()
    {
        return $this->signature;
    }

    /**
     * Get the value of publicId
     */ 
    public function getPublicId()
    {
        return $this->publicId;
    }

    /**
     * Get the value of email
     */ 
    public function getEmail()
    {
        return $this->email;
    }

    /**
     * Get the value of processId
     */ 
    public function getprocessId()
    {
        return $this->processId;
    }
}