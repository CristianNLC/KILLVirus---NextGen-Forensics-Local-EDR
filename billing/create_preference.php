<?php
// C:\wamp64\www\Proyecto_Antivirus\billing\create_preference.php

function load_env_php($env_path) {
    if (file_exists($env_path)) {
        $lines = file($env_path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '' || strpos($line, '#') === 0) continue;
            if (strpos($line, '=') !== false) {
                list($key, $val) = explode('=', $line, 2);
                $key = trim($key);
                $val = trim(trim($val), '"\'');
                if (!getenv($key)) {
                    putenv("{$key}={$val}");
                    $_ENV[$key] = $val;
                }
            }
        }
    }
}

load_env_php(__DIR__ . '/../.env');

$mp_access_token = getenv('MP_ACCESS_TOKEN') ?: ($_ENV['MP_ACCESS_TOKEN'] ?? '');

$preference_data = [
    "items" => [
        [
            "title"       => "KILLVirus PRO - Licencia Anual (1 PC)",
            "quantity"    => 1,
            "unit_price"  => 15000, // Precio en moneda local
            "currency_id" => "ARS"
        ]
    ],
    "back_urls" => [
        "success" => "http://localhost/Proyecto_Antivirus/billing/success.php",
        "failure" => "http://localhost/Proyecto_Antivirus/billing/failure.php"
    ],
    "auto_return" => "approved",
    "notification_url" => "https://TU-DOMINIO-O-NGROK/Proyecto_Antivirus/billing/webhook_mp.php"
];

$ch = curl_init("https://api.mercadopago.com/checkout/preferences");
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($preference_data));
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    "Authorization: Bearer {$mp_access_token}",
    "Content-Type: application/json"
]);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
$response = curl_exec($ch);
curl_close($ch);

$data = json_decode($response, true);

// Devuelve la URL a la que debes redirigir al usuario para pagar
if (isset($data['init_point'])) {
    echo "Enlace de pago: " . $data['init_point'];
} else {
    echo "Error al crear preferencia: " . $response;
}