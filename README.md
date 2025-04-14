# Scripts para operar con el KeyVault de Xbox 360
Este repositorio cuenta con:
- Script para des-encriptar KeyVault extraído de una nand para Xbox 360.
- Script para extraer llaves públicas en el KeyVault.
- Código Java para des-encriptar y extraer llaves públicas del KeyVault extraído de una nand para Xbox 360.

# Como usar decryptKv.py
* Editar el .py e ingresar la CPU-KEY
* Ejecutar <code>python decryptKv.py</code> y esperar a que se genere el archivo <b>keyvault_dec.bin</b>

# Como usar keyExtract.py
* Ejecutar <code>python keyExtract.py</code> y esperar a que se generen los archivos de llaves detectadas.

# Como usar JKeyVaultTools.java
* Elegir el IDE Java de tu preferencia (Netbeans en mi caso)
* Crear un nuevo proyecto y copiar el contenido del archivo JKeyVaultTools.java (modificar el nombre de la clase principal)
* Ejecutar y esperar la generación de archivos correspondientes.
