<?php
// C:\wamp64\www\Proyecto_Antivirus\billing\create_preference.php

function load_env_php() {
    $envPath = __DIR__ . '/../.env';
    if (!file_exists($envPath)) {
        return [];
    }
    $lines = file($envPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $env = [];
    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '' || str_starts_with($line, '#')) continue;
        if (str_contains($line, '=')) {
            list($name, $value) = explode('=', $line, 2);
            $name = trim($name);
            $value = trim($value, " \t\n\r\0\x0B\"'");
            putenv("{$name}={$value}");
            $_ENV[$name] = $value;
            $env[$name] = $value;
        }
    }
    return $env;
}

load_env_php();

$mp_access_token = getenv('MP_ACCESS_TOKEN') ?: ($_ENV['MP_ACCESS_TOKEN'] ?? '');

if (empty($mp_access_token)) {
    die("Error: No se encontró el MP_ACCESS_TOKEN en el archivo .env");
}

// 1. Configurar la preferencia de pago
// 1. Configurar la preferencia de pago
    $preference_data = [
        "items" => [
            [
                "title"       => "KILLVirus PRO - Licencia Anual (1 PC)",
                "quantity"    => 1,
                "unit_price"  => 15000,
                "currency_id" => "ARS"
            ]
        ],
        "back_urls" => [
            "success" => "http://localhost/Proyecto_Antivirus/billing/success.php",
            "failure" => "http://localhost/Proyecto_Antivirus/billing/failure.php",
            "pending" => "http://localhost/Proyecto_Antivirus/billing/pending.php"
        ]
        // Se omite "auto_return" en localhost para evitar el rechazo de la API
    ];

$ch = curl_init("https://api.mercadopago.com/checkout/preferences");
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($preference_data));
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    "Authorization: Bearer {$mp_access_token}",
    "Content-Type: application/json"
]);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // Evita fallos de certificados SSL en local
$response = curl_exec($ch);
curl_close($ch);

$data = json_decode($response, true);

if (isset($data['init_point'])) {
    header("Location: " . $data['init_point']);
    exit;
} else {
    echo "<h3>Error al crear preferencia:</h3>";
    echo "<pre>";
    print_r($response);
    echo "</pre>";
}