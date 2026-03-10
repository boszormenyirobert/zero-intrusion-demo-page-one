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
    private string $secret;
    private string $corporateKey;
    private string $publicId;
    private string $hub = 'https://hub.zero-intrusion.com';
    private string $userRegistration = '/api/user-registration';
    private string $userLogin = '/api/user-login';


    public function __construct(
        private ContainerBagInterface $params,
        private LoggerInterface $logger,
        private EntityManagerInterface $entityManager
    ) {        
        $this->secret = $this->params->get('CORPORATE_ID_SECRET');
        $this->corporateKey = $this->params->get('CORPORATE_ID_KEY');
        $this->publicId = $this->params->get('CORPORATE_ID');
    }

    /**
     * Home page endpoint
     */
    #[Route('/', name: 'home', methods: ['GET'])]
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

    /**
     * This endpoint initiates the registration process by generating a QR code and sending it to the frontend.
     * Sends in the header the corporate key and a timestamp, signed with the secret, to authenticate the request to the system hub (API).
     */
    #[Route('/registration', name: 'registration', methods: ['GET'])]
    public function registration(HttpClientInterface $client)
    {
        $timestamp     = time();
        $hmac = hash_hmac('sha256', "{$this->corporateKey}|{$timestamp}", $this->secret);

        $headers = [
            'Content-Type'   => 'application/json',
            'X-Client-Auth'  => $hmac,
        ];

        $payload = [
            'publicId' => $this->publicId,
            'message'  => $this->corporateKey,
            'domain'   => $this->hub,
        ];

        $response   = $client->request('POST', $this->hub . $this->userRegistration, [
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


    /**
     * Called by the system hub when the user completes the registration process on their mobile device.
     * It verifies the SSL signature and creates the user record if valid.
     */
    #[Route('/api/registration/callback', name: 'registration_callback', methods: ['POST'])]
    public function registrationCallback(
        Request $request
    ) {   
        $response = json_decode($request->getContent(), true, 512, JSON_THROW_ON_ERROR);
        $dto = RegistrationProcessDTO::mapFromArrayRegistration($response);

        $ok = $this->sslValidation($dto);       
        if ($ok === 1) {
            $this->logger->critical("Signature is valid.");
            $this->createUser($dto);
        } elseif ($ok === 0) {
            $this->logger->critical("Signature is invalid.");
        } else {
            $this->logger->critical("Error during signature verification: " . openssl_error_string());
        }        

        return new JsonResponse(['status' => 'ok','error' => 'Invalid signature'], 200);
    }

    /**
     * This endpoint initiates the login process by generating a QR code and sending it to the frontend.
     * Sends in the header the corporate key and a timestamp, signed with the secret, to authenticate the request to the system hub (API).
     */
    #[Route('/login', name: 'login', methods: ['GET'])]
    public function login(
        HttpClientInterface $client,
        Request $request
    ) {   

        $userPublicId = null;

        if ($request->query->has('userPublicId')) {
            $userPublicId = $request->query->get('userPublicId');

            if ($userPublicId === null) {
                return;
            }

            // Length check
            if (strlen($userPublicId) !== 48) {
                throw new \InvalidArgumentException('Invalid length.');
            }

            // Base64 karakter whitelist
            if (!preg_match('/^[A-Za-z0-9+\/]+={0,2}$/', $userPublicId)) {
                throw new \InvalidArgumentException('Invalid characters.');
            }

            // Strict decode
            $decoded = base64_decode($userPublicId, true);

            if ($decoded === false || strlen($decoded) !== 35) {
                throw new \InvalidArgumentException('Invalid token.');
            }
        }

        $timestamp = time();
        $hmac = hash_hmac('sha256', $this->corporateKey . '|' . $timestamp, $this->secret);
        
        $header = [
            'Content-Type' => 'application/json',
            'X-Client-Auth' => $hmac
        ];       

        $response = $client->request('POST', $this->hub . $this->userLogin, [
            'headers' => $header,
            'body' => json_encode([
                "publicId" => $this->publicId,
                "message" => $this->corporateKey,
                "domain" => $this->hub,
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

    /**
     * Called by the system hub when the user completes the login process on their mobile device.
     * It verifies the SSL signature and updates the user record to allow access.
     */
    #[Route('/api/user-login/callback', name: 'user_login_callback', methods: ['POST'])]
    public function systemHubLoginCallback(
        Request $request,
        UserRepository $userRepository
        )
    {
        $response = json_decode($request->getContent(), true, 512, JSON_THROW_ON_ERROR);
        $dto = RegistrationProcessDTO::mapFromArrayLogin($response);
        $ok = $this->sslValidation($dto);       
        if ($ok === 1) {
            $this->logger->critical("Signature is valid.");

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

        } elseif ($ok === 0) {
            $this->logger->critical("Signature is invalid.");
            return new JsonResponse(['status' => 'ok','error' => 'Invalid signature'], 200);
        } else {
            $this->logger->critical("Error during signature verification: " . openssl_error_string());
            return new JsonResponse(['status' => 'ok','error' => 'Invalid signature'], 200);
        }
    }    

    /**
     * Polled by the frontend to check if the user has completed the login process.
     * If successful, returns a JWT token and sets it as a cookie.
     */
    #[Route('/user-login/check', name: 'user_login_check', methods: ['GET'])]
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

    /**
     * This endpoint logs out the user by clearing the JWT token cookie and redirecting to the home page.
     */
    #[Route('/logout', name: 'logout', methods: ['GET'])]
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
