import hashlib
import random
import binascii
import time
import sys

# ------ Definicion de funciones ------

# Funcion main que se utiliza en modo de menu para el usuario
# Entradas: ninguna
# Salidas: ninguna
def main():

    flag = '0'

    while(flag != '3'):
        print "OPCION 1: CIFRAR UN MENSAJE\n"
        print "OPCION 2: DESCIFRAR UN MENSAJE\n"
        print "OPCION 3: SALIR DEL PROGRAMA\n"

        flag = raw_input ("Ingrese un opcion: ")

        if flag == '1':
            myMessage = raw_input ("Ingrese mensaje a encriptar ")
            t0 = time.time()
            translated, key, mac = cbc_encrypt(myMessage)
            t1 = time.time()
            print "El mensaje cifrado es: " + translated
            print "La llave usada es: " + key
            print "El MAC concatenado al mensaje cifrado es: " + mac
            print "Tiempo de cifrado: " + str(t1-t0) + " segundos\n"


        elif flag == '2':
            myMessage = raw_input ("Ingrese mensaje a desencriptar: ")
            myKey = raw_input ("Ingrese clave para desencriptar: ")
            t0 = time.time()
            translated = cbc_desencrypt(myMessage, myKey)
            t1 = time.time()
            print "El mensaje descifrado es: " + translated
            print "Tiempo de descifrado: " + str(t1 - t0) + " segundos\n"


        elif flag == '3':
            print "BYE BYE"


        else:
            print("Ingrese opcion correcta\n ")

        print "#################################\n"

    return


# Funcion que llama a los cifradores para cifrar el mensaje
# Entradas: la llave, y el mensaje a cifrar
# Salidas: el mensaje cifrado
def encryptMessage(message, key):
    
    firstCypher = myCypher(message, key)
    secondCypher = vigenere(binascii.hexlify(key),binascii.hexlify(firstCypher), 'encrypt')
    return secondCypher


# Funcion que llama a los descifradores para descifrar un mensaje
# Entradas: la llave, y un mensaje cifrado
# Salidas: el mensaje original descifrado
def decryptMessage(key, message):
    firstDecypher = vigenere(key, message, 'decrypt')
    secondDecypher = myDecypher(firstDecypher,key)
    return secondDecypher


# Funcion que crea una llave a partir del mensaje
# Entradas: el mensaje
# Salidas: una llave para cifrar el mensaje
def createKey(message):
    length = len(message)
    count = 0
    key = ""
    for i in range(0,length):
        randomNumber = random.randint(0,9)
        randomNumber = str(randomNumber)
        key = key + message[i]
        key = key + randomNumber

    # Luego de agregar numeros al azar, se procede a
    # realizar un hash de tipo sha1
    finalKey = hashlib.sha1(key).digest()
    return finalKey

# Funcion personalizada para realizar un cifrado
# Entrada: mensaje a cifrar, y la llave a utilizar en el cifrado
# Salida: mensaje cifrado
def myCypher(message, key):
    message = bytearray(message)
    key = bytearray(key)
    result = message

    count = 0

    for x in range(0,len(message)):
        result[x] = message[x]^key[count]
        count+=1
        if (count>=len(key)):
            count = 0

    return result

# Funcion que resuelve un mensaje cifrado por myCypher
# Entradas: el mensaje a descifrar, y la llave correspondiente
# Salidas: el mensaje traducido
def myDecypher(message,key):
    a = is_hex(message)
    b = is_hex(key)
    if(a and b):

        message = bytearray.fromhex(message)
        key = bytearray.fromhex(key)
        result = message

        count = 0

        for x in range(0,len(message)):
            result[x] = message[x]^key[count]
            count+=1
            if (count>=len(key)):
                count = 0

        return result
    else:
        print "\nValores hexadecimales no validos"
        sys.exit()


# Funcion que realiza el cifrado de Vigenere
# Entrada: llave del cifrado, el mensaje a cifrar o descifrar, y el modo a ejecutar, que corresponde a un string 'encrypt' o 'decrypt'
# Salida: texto cifrado con vigenere
def vigenere(key, message, mode):
    translated = [] # stores the encrypted/decrypted message string

    keyIndex = 0
    #key = key.upper()

    for symbol in message: # loop through each character in message
        num = LETTERS.find(symbol)
        if num != -1: # -1 means symbol.upper() was not found in LETTERS
            if mode == 'encrypt':
                num += LETTERS.find(key[keyIndex]) # add if encrypting
            elif mode == 'decrypt':
                num -= LETTERS.find(key[keyIndex]) # subtract if decrypting

            num %= len(LETTERS) # handle the potential wrap-around

             # add the encrypted/decrypted symbol to the end of translated.
            #if symbol.isupper():
            translated.append(LETTERS[num])
            #elif symbol.islower():
            #    translated.append(LETTERS[num].lower())

            keyIndex += 1 # move to the next letter in the key
            if keyIndex == len(key):
                keyIndex = 0
        else:
            # The symbol was not in LETTERS, so add it to translated as is.
            translated.append(symbol)

    return ''.join(translated)

# Funcion que verifica que s sea un hexadecimal valido
# entrada: el string s
# salida: verdadero o falso dependiendo si s corresponde a un hexadecimal valido
def is_hex(s):
    try:
        bytearray.fromhex(s)
        return True
    except:
        return False


# Funcion encargada de dividir el mensaje en bloques y encriptar
# Entrada: mensaje a encriptar
# Salida: mensaje encriptado, llave con la cual se encripto y mac
def cbc_encrypt(message):

    blocksArray = []
    lengthMsg = len(message)
    while (lengthMsg > 64):
        blocksArray.append(message[len(message)-lengthMsg:len(message)-lengthMsg+64])
        lengthMsg-=64

    blocksArray.append(message[len(message)-lengthMsg:len(message)])
    key = createKey(message)

    print "Se divide mensaje en " + str(len(blocksArray)) + " bloques"

    encryptedMessage = ""
    encryptedBlock = encryptMessage(blocksArray[0], key)
    encryptedMessage+=encryptedBlock
    for block in blocksArray[1:]:
        xorResult = myCypher(block, encryptedBlock)
        encryptedBlock = encryptMessage(xorResult, key)
        encryptedMessage+=encryptedBlock

    mac = genMac(encryptedBlock)
    encMesgWithMac = encryptedMessage+mac
    return encMesgWithMac, binascii.hexlify(key), mac

# Funcion encargada de dividir el mensaje cifrado para desencriptarlo
# Entrada: mensaje encriptado, llave
# Salida: mensaje desencriptado
def cbc_desencrypt(message, key):
    blocksArray = []
    
    mac = message[-32:len(message)]
    print "Se extrae MAC igual a: " + mac

    message = message[:-32]
    lengthMsg = len(message)

    while (lengthMsg > 128):
        blocksArray.append(message[len(message)-lengthMsg:len(message)-lengthMsg+128])
        lengthMsg-=128

    blocksArray.append(message[len(message)-lengthMsg:len(message)])

    print "Mensaje se descifra en " + str(len(blocksArray)) + " bloques"

    decryptedMessage = ""
    decryptedMessage += decryptMessage(key, blocksArray[0])
    encryptedBlock = blocksArray[0]
    print(decryptedMessage)
    for block in blocksArray[1:]:
        decryptedBlock = decryptMessage(key, block)

        xorResult = myCypher(decryptedBlock, encryptedBlock)
        encryptedBlock = block
        decryptedMessage+=xorResult

    return decryptedMessage

# Funcion encargada de generar el MAC a partir del ultimo bloque
# Entrada: Ultimo bloque cifrado
# Salida: MAC
def genMac(lastBlock):
    if (len(lastBlock)<32):
        lastBlock = lastBlock.ljust(32, '0')

    return lastBlock[0:32]



# ------ Cuerpo del programa ------

random.seed()

print "############################################################"
print "####### PROGRAMA DE CIFRADO Y DESCIFRADO DE MENSAJES #######"
print "############################################################\n"

# alfabeto utilizado por el primer cifrado
LETTERS = "abcdef0123456789"

#Llamo a la funcion principal del menu
main()

