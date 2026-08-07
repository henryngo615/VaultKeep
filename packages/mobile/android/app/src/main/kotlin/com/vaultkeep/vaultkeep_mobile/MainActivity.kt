package com.vaultkeep.vaultkeep_mobile

import io.flutter.embedding.android.FlutterFragmentActivity

// local_auth's Android implementation requires a FragmentActivity host
// (it shows the biometric prompt via the AndroidX BiometricPrompt API).
class MainActivity : FlutterFragmentActivity()
