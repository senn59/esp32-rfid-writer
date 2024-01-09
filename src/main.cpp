#include <SPI.h>
#include <MFRC522.h>

#define RST_PIN 22
#define SS_PIN 21
#define SIZE_BUFFER 18
#define MAX_SIZE_BLOCK 16

byte bufferToWrite[MAX_SIZE_BLOCK] = {0};

MFRC522::MIFARE_Key key;
MFRC522 mfrc522;   // Create MFRC522 instance.
bool canWrite = false;

boolean validateInput(String input);
String writeCard(String input);
void convert_string_to_buffer(String input, byte *buffer, byte bufferSize);

boolean auth();
void stopauth();
boolean read();
boolean write(byte *data);

String message;

void setup() {
  Serial.begin(9600); // Initialize serial communications with the PC
  SPI.begin();        // Init SPI bus

  mfrc522.PCD_Init(SS_PIN, RST_PIN); // Init each MFRC522 card
  // Serial.print(F("Reader "));
  // Serial.print(F(": "));
  // mfrc522.PCD_DumpVersionToSerial();
}

void dump_byte_array(byte *buffer, byte bufferSize) {
  for (byte i = 0; i < bufferSize; i++) {
    Serial.print(buffer[i]);
    Serial.print(" ");
  }
  Serial.print("\n");
}

void loop() {
  if (Serial.available() > 0)
  {
    char received = Serial.read();
    if (received == '\n')
    {
      if (validateInput(message)) {
        convert_string_to_buffer(message, bufferToWrite, MAX_SIZE_BLOCK);
        canWrite = true;
      } else {
        Serial.println("error: invalid message");
      }
      message = ""; 
    }
    else 
    {
      message += received;
    }
  }

  if (mfrc522.PICC_IsNewCardPresent() && mfrc522.PICC_ReadCardSerial()) {
    for (byte i = 0; i < 6; i++) key.keyByte[i] = 0xFF;
    byte block = 1;

    if (!auth()) {
      Serial.println("error: cant authenticate");
      return;
    }
    if (canWrite) {
      boolean success = write(bufferToWrite);
      if (!success) {
        Serial.println("error: could not write");
      } else {
        Serial.println("ok: wrote card successfully");
      }
      canWrite = false;
    } else {
      boolean success = read();
      if (!success) {
        Serial.println("error: could not read");
      } else {
        Serial.println("ok: read card successfully");
      }
    }
    stopauth();
  }
}

boolean validateInput(String input) {
  int length = input.length();
  if (length == 0 || length > MAX_SIZE_BLOCK) {
    return false;
  }
  return true;
}

void convert_string_to_buffer(String input, byte *buffer, byte bufferSize) {
  int idLength = input.length();
  for (int i = 0; i < bufferSize; i++) {
    if (i < idLength) {
      buffer[i] = byte(input[i]);
    } else {
      buffer[i] = 0x00;
    }
  }
}

boolean read() {
  byte size = SIZE_BUFFER;
  byte readBuffer[SIZE_BUFFER] = {0};
  byte block = 1;
  MFRC522::StatusCode status = mfrc522.MIFARE_Read(block, readBuffer, &size);
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("error: Operation failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
    return false;
  }
  dump_byte_array(readBuffer, size);
  return true;
}

boolean write(byte *data) {
  byte block = 1;
  MFRC522::StatusCode status = mfrc522.MIFARE_Write(block, data, MAX_SIZE_BLOCK);
  if (status != MFRC522::STATUS_OK) {
    Serial.println(mfrc522.GetStatusCodeName(status));
    return false;
  }
  dump_byte_array(data, MAX_SIZE_BLOCK);
  return true;
}

boolean auth() {
  byte block = 1;
  MFRC522::StatusCode status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, block, &key, &(mfrc522.uid));
  if (status != MFRC522::STATUS_OK) {
    Serial.println(mfrc522.GetStatusCodeName(status));
    return false;
  }
  return true;
}

void stopauth() {
  mfrc522.PICC_HaltA();
  mfrc522.PCD_StopCrypto1();
}