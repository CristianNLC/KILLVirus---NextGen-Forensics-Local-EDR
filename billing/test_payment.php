<?php
// C:\wamp64\www\Proyecto_Antivirus\billing\test_payment.php

// Datos simulados que enviaría Mercado Pago tras un cobro exitoso
$fake_event = [
    "type" => "payment",
    "data" => [
        "id" => "999999999" // ID ficticio de transacción
    ]
];

$ch = curl_init("http://localhost/Proyecto_Antivirus/billing/webhook_mp.php");
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($fake_event));
curl_setopt($ch, CURLOPT_HTTPHEADER, ["Content-Type: application/json"]);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

$response = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

echo "Código HTTP: {$http_code}\n";
echo "Respuesta del Webhook: {$response}\n";