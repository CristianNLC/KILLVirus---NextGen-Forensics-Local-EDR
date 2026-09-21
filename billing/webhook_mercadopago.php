<?php
// Recibe el ping de Mercado Pago cuando el cobro fue aprobado
$body = file_get_contents('php://input');
$data = json_decode($body, true);

if (isset($data['type']) && $data['type'] === 'payment') {
    $payment_id = $data['data']['id'];
    
    // 1. Consultar estado a la API de Mercado Pago con tu ACCESS_TOKEN
    // 2. Si status == 'approved', obtener el email del pagador y monto
    // 3. Ejecutar: python core/license_manager.py o hacer el POST directo a Supabase
    // 4. Enviar email al cliente con su clave KV-PRO-XXXX-XXXX
}
http_response_code(200);