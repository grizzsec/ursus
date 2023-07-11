# URSUS
La herramienta de análisis de malware "Ursus" es una aplicación que te permite realizar diversas tareas de análisis sobre archivos ejecutables, con el objetivo de detectar posibles amenazas de malware.

#A continuación se detallan las principales funciones de la herramienta:

Análisis del archivo PE: Esta función carga un archivo ejecutable en formato PE (Portable Executable) y muestra información básica sobre el archivo, como su nombre, tamaño y número de entradas en la tabla de importación. También muestra información detallada sobre cada sección del archivo, como el tamaño y contenido de los primeros bytes de cada sección.

Análisis de código ensamblador: Esta función extrae la sección de código del archivo PE y realiza un análisis de su contenido utilizando la biblioteca Capstone. Muestra el código ensamblador de la sección de código, incluyendo las direcciones de memoria, las instrucciones y los operandos correspondientes.

Análisis con reglas YARA: Esta función utiliza reglas YARA, que son patrones predefinidos que pueden identificar características específicas de malware, para realizar un análisis de coincidencias en el contenido del archivo. Si se encuentra alguna coincidencia, se muestra la regla YARA correspondiente.

Ejecución en sandbox: Esta función ejecuta el archivo en un entorno aislado conocido como sandbox, lo que permite observar el comportamiento del archivo sin poner en riesgo el sistema principal. Esto es especialmente útil para identificar posibles actividades maliciosas del archivo.

#Para ejecutar la herramienta "Ursus", simplemente debes seguir los siguientes pasos:

Ejecuta el código en Python en un entorno que tenga instaladas las bibliotecas requeridas: tkinter, pefile, capstone y yara.

Una vez ejecutada la aplicación, se abrirá una ventana con una interfaz gráfica.

Haz clic en el botón "Abrir archivo" para seleccionar el archivo ejecutable que deseas analizar.

A continuación, se te pedirá que selecciones el archivo YARA con las reglas de análisis. Puedes proporcionar tus propias reglas YARA o utilizar las disponibles en línea.

Después de seleccionar el archivo y las reglas, la herramienta llevará a cabo las diferentes etapas de análisis: análisis del archivo PE, análisis de código ensamblador y análisis con reglas YARA.

Si se detecta una posible actividad de ransomware durante el análisis, se te preguntará si deseas eliminar el archivo. Puedes aceptar o cancelar la eliminación según tu preferencia.

Además, el archivo se ejecutará en un sandbox, lo que permite observar su comportamiento en un entorno aislado.

Una vez completado el análisis, se mostrarán ventanas de diálogo con la información obtenida, como los detalles del archivo, la información de las secciones, las coincidencias con las reglas YARA, entre otros.
