<?php

namespace App\Controller\User;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\Routing\Annotation\Route;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use App\DTO\RegistrationProcessDTO;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Doctrine\ORM\EntityManagerInterface;
use App\Repository\UserRepository;
use Symfony\Component\HttpFoundation\Cookie;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTTokenManagerInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Encoder\JWTEncoderInterface;
use Symfony\Component\DependencyInjection\ParameterBag\ContainerBagInterface;

class UserController extends AbstractController
{
    public function __construct(
         private ContainerBagInterface $params,
        private LoggerInterface $logger,
        private EntityManagerInterface $entityManager
    ) {}

    #[Route('/', name: 'home', methods: "GET")]
    public function index(    
        Request $request,
        JWTEncoderInterface $jwtEncoder,
        UserRepository $userRepository    
    ) {   
        $jwtTokenEncoded = $request->cookies->get('jwt_token') ?? '';   
        $this->logger->critical("JWT Token from cookie: " . $jwtTokenEncoded);

        if($jwtTokenEncoded){
            $jwt_token = $jwtEncoder->decode($jwtTokenEncoded);

            if ($jwt_token) {           
                $email = $jwt_token['username'] ?? 'n/a';
                $user = $userRepository->findOneBy(['email' => $email]);
                if($user){
                    return $this->render('home.html.twig', [
                        'user' => $user->getEmail() ?? null,
                        'userPublicId' => $user->getPublicId() ?? null       
                    ]);
                }
            }
        }

        
        return $this->render('home.html.twig', [
            'user' => null           
        ]);
    }

    #[Route('/registration', name: 'registration', methods: ['GET'])]
    public function registration(HttpClientInterface $client)
    {
        $timestamp     = time();
        $secret        = $this->params->get('CORPORATE_ID_SECRET');
        $corporateKey  = $this->params->get('CORPORATE_ID_KEY');
        $publicId      = $this->params->get('CORPORATE_ID');
        $domain        = 'http://zerodemo.local/';
        $target        = 'http://zeroproxyapi.local:8082/api/user-registration';

        $hmac = hash_hmac('sha256', "{$corporateKey}|{$timestamp}", $secret);

        $headers = [
            'Content-Type'   => 'application/json',
            'X-Client-Auth'  => $hmac,
        ];

        $payload = [
            'publicId' => $publicId,
            'message'  => $corporateKey,
            'domain'   => $domain,
        ];

        $response   = $client->request('POST', $target, [
            'headers' => $headers,
            'json'    => $payload,
        ]);

        $responseQR = $response->toArray();

        $qr = json_decode($response->getContent(), true);

        return $this->render('qr-action.html.twig', [
            'processId' => $qr['registrationProcessId'],
            'qrCode'     => $responseQR['qrCode'] ?? null,
        ]);
    }


    #[Route('/api/registration/callback', name: 'registration_callback', methods: "POST")]
    public function registrationCallback(
        Request $request
    ) {   
        $response = json_decode($request->getContent(), true, 512, JSON_THROW_ON_ERROR);
        $dto = RegistrationProcessDTO::mapFromArrayRegistration($response);

        $this->createUser($dto);

        return new JsonResponse(['status' => 'ok'], 200);
    }

    #[Route('/login', name: 'login', methods: "GET")]
    public function login(
        HttpClientInterface $client,
        Request $request
    ) {   

        $userPublicId = null;
        if ($request->query->has('userPublicId')) {
            $userPublicId = $request->query->get('userPublicId');
        }

        $timestamp     = time();
        $secret        = $this->params->get('CORPORATE_ID_SECRET');
        $corporateKey  = $this->params->get('CORPORATE_ID_KEY');
        $publicId      = $this->params->get('CORPORATE_ID');
        $domain        = 'http://zerodemo.local/';
        $target = "http://zeroproxyapi.local:8082/api/user-login";


        $hmac = hash_hmac('sha256', $corporateKey . '|' . $timestamp, $secret);
        
        $header = [
            'Content-Type' => 'application/json',
            'X-Client-Auth' => $hmac
        ];       

        $response = $client->request('POST', $target, [
            'headers' => $header,
            'body' => json_encode([
                "publicId" => $publicId,
                "message" => $corporateKey,
                "domain" => $domain,
                "userPublicId" => $userPublicId
            ], \JSON_THROW_ON_ERROR)
        ]);
    
        $responseQR = json_decode($response->getContent(),true);

        return $this->render('qr-action.html.twig', [
                'processId' => $responseQR['domainProcessId'],
                'qrCodeData' => $responseQR,
                'qrCode' => $responseQR['qrCode'],
                'user' => null     
        ]);
    }    

    #[Route('/api/user-login/callback', name: 'user_login_callback', methods: ["POST"])]
    public function systemHubLoginCallback(
        Request $request,
        UserRepository $userRepository
        )
    {
        $response = json_decode($request->getContent(), true, 512, JSON_THROW_ON_ERROR);
        $dto = RegistrationProcessDTO::mapFromArrayLogin($response);
        $user = $userRepository->findOneBy([
            'publicId' => $dto->getPublicId(),
            'email' => $dto->getEmail()
        ]);

        $user->setAllowed(true);
        $user->setProcess($dto->getProcessId());
        $this->entityManager->persist($user);
        $this->entityManager->flush();

        $this->logger->critical("Login callback received: " . json_encode((array)$user));

        return new JsonResponse(['status' => 'ok'], 200);
    }    

    #[Route('/user-login/check', name: 'user_login_check', methods: "GET")]
    public function userLoginCheck(
        Request $request,
        UserRepository $userRepository,
        JWTTokenManagerInterface $jwtManager
    )
    {
        $processId = $request->query->get('processId');
        $user = $userRepository->findOneBy([
            'process' => $processId
        ]);
       
        if($user && $user->isAllowed()){            
            $token = $jwtManager->create($user);
            $response = new JsonResponse([
                'message' => 'Authentication is success',
                'jwt_token' => $token
            ]);

            //$response = $this->redirectToRoute('home');

            $cookie = new Cookie(
                'jwt_token',
                $token,
                time() + 3600, // expire in 1h
                '/',
                null,
                false,  // secure (set to true on HTTPS)
                true,   // httpOnly
                false,
                'Strict'
            );

            $response = $this->json([
                'message' => 'Authentication success.'
            ]);

            $response->headers->setCookie($cookie);

            return $response;
        }

        return $this->json(['message' => 'Unsuccess authentication.']);
    }     

    #[Route('/logout', name: 'logout', methods: "GET")]
    public function logout(    
        Request $request,
        JWTEncoderInterface $jwtEncoder,
        UserRepository $userRepository    
    ) {   
        $response = $this->redirectToRoute('home');

        $response->headers->clearCookie('jwt_token', '/', null, false, true, 'Strict');

        return $response;
    }

    private function createUser(RegistrationProcessDTO $process): void
    {
        $ok = $this->sslValidation($process);

        if ($ok === 1) {
            $this->logger->critical("Signature is valid.");

            $user = new \App\Entity\User();
            $user->setPublicId($process->getPublicId());
            $user->setEmail($process->getEmail());
            $user->setProcess($process->getProcessId());

            $this->entityManager->persist($user);
            $this->entityManager->flush();

        } elseif ($ok === 0) {
            $this->logger->critical("Signature is invalid.");
        } else {
            $this->logger->critical("Error during signature verification: " . openssl_error_string());
        }
    }

    private function sslValidation(RegistrationProcessDTO $process): int|false
    {
        $receivedSignature = base64_decode($process->getSignature(), true);
        if ($receivedSignature === false) {
            $this->logger->critical('Failed to base64 decode signature.');
            return false;
        }

        $userIdentity = json_encode(
            [
                'publicId' => $process->getPublicId(),
                'email'    => $process->getEmail(),
            ]
        );

        $publicKeyPem = $this->params->get('PUBLIC_KEY');

        $publicKey = openssl_pkey_get_public($publicKeyPem);

        $keyDetails = openssl_pkey_get_details(openssl_pkey_get_public($publicKeyPem));
        $this->logger->critical('Length: ' . $keyDetails['bits']);
        $this->logger->critical('UserIdentity : ' . $userIdentity);
        $result = openssl_verify($userIdentity, $receivedSignature, $publicKey, OPENSSL_ALGO_SHA256);
        unset($publicKey);
        $this->logger->critical('SSL openssl_verify is valid : ' . $result);

        return $result;
    }
}
