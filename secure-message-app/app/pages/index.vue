<script setup lang="ts">
import { ref, computed } from 'vue'
import { encryptMessage, decryptMessage } from '~/utils/crypto'

definePageMeta({
  ssr: false
})

/* ---------------- STATE ---------------- */

const mode = ref<'encrypt' | 'decrypt'>('encrypt')

const password = ref('')
const text = ref('')
const loading = ref(false)

const isEncrypt = computed(() => mode.value === 'encrypt')

function switchMode(newMode: 'encrypt' | 'decrypt') {
  mode.value = newMode
}

/* ---------------- SECURITY HELPERS ---------------- */

function validateInput() {
  if (!password.value.trim()) {
    alert('Password is required.')
    return false
  }

  if (!text.value.trim()) {
    alert('Message cannot be empty.')
    return false
  }

  return true
}

/* ---------------- MAIN ACTION ---------------- */

async function handleAction() {
  if (!validateInput()) return

  loading.value = true

  try {
    if (isEncrypt.value) {
      const encrypted = await encryptMessage(
        text.value,      // ✅ message first
        password.value   // ✅ password second
      )

      text.value = encrypted
    } else {
      const decrypted = await decryptMessage(
        text.value,      // ✅ encrypted payload first
        password.value   // ✅ password second
      )

      text.value = decrypted
    }

    password.value = ''

  } catch (err) {
    console.error(err)

    alert(
      isEncrypt.value
        ? 'Encryption failed.'
        : 'Decryption failed. Wrong password or invalid message.'
    )
  } finally {
    loading.value = false
  }
}

</script>

<template>
  <div class="card">

    <h1 style="margin-bottom:20px;">
      Secure Message Tool 🔐 .⋆♱
    </h1>

    <!-- Tabs -->
    <div class="tabs">
      <div
        class="tab"
        :class="{ active: mode === 'encrypt' }"
        @click="switchMode('encrypt')"
      >
        Encrypt
      </div>

      <div
        class="tab"
        :class="{ active: mode === 'decrypt' }"
        @click="switchMode('decrypt')"
      >
        Decrypt
      </div>
    </div>

    <!-- Animated View Switch -->
    <Transition name="fade" mode="out-in">

      <div :key="mode">

        <div class="input-group">
          <label>Password</label>
          <input
            type="password"
            v-model="password"
            autocomplete="new-password"
            placeholder="Enter your secret password..."
          />
        </div>

        <div class="input-group">
          <label>
            {{ isEncrypt ? "Message to encrypt" : "Encrypted message" }}
          </label>

          <textarea
            v-model="text"
            :placeholder="isEncrypt
              ? 'Write message to encrypt...'
              : 'Paste encrypted message...'">
          </textarea>
        </div>

        <button
          class="primary-btn"
          :disabled="loading"
          @click="handleAction"
        >
          {{ loading
            ? "Processing..."
            : (isEncrypt ? "Encrypt Message" : "Decrypt Message")
          }}
        </button>

      </div>

    </Transition>

  </div>
</template>
