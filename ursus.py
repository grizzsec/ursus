import tkinter as tk
from tkinter import filedialog, messagebox
import pefile
import capstone
import yara
import os
import shutil
import subprocess

def analizar_archivo_pe(ruta_archivo):
    try:
        # Cargar el archivo PE
        pe = pefile.PE(ruta_archivo)

        # Imprimir información básica del archivo
        informacion = f"Nombre del archivo: {pe.get_filename()}\n"
        informacion += f"Tamaño del archivo: {pe.OPTIONAL_HEADER.SizeOfImage} bytes\n"
        informacion += f"Entradas en la tabla de importación: {len(pe.DIRECTORY_ENTRY_IMPORT)}"
        messagebox.showinfo("Información del archivo", informacion)

        # Obtener secciones del archivo
        secciones = pe.sections

        # Analizar cada sección
        for seccion in secciones:
            nombre_seccion = seccion.Name.decode('utf-8').rstrip('\x00')
            informacion_seccion = f"\n== Sección: {nombre_seccion} ==\n"
            informacion_seccion += f"Tamaño de la sección: {seccion.SizeOfRawData} bytes\n"

            # Obtener los primeros bytes de la sección
            bytes_seccion = seccion.get_data()[:256]
            informacion_seccion += "Contenido de los primeros bytes de la sección:\n"
            informacion_seccion += bytes_seccion.hex()
            messagebox.showinfo("Información de la sección", informacion_seccion)

            # Realizar análisis adicional de la sección
            # Aquí puedes implementar tus propias técnicas de análisis de malware

    except pefile.PEFormatError as e:
        messagebox.showerror("Error", f"Error al analizar el archivo PE: {e}")

def analizar_codigo_ensamblador(ruta_archivo):
    try:
        # Cargar el archivo PE
        pe = pefile.PE(ruta_archivo)

        # Obtener la dirección base de carga del archivo PE
        base_address = pe.OPTIONAL_HEADER.ImageBase

        # Crear el objeto de análisis de código ensamblador
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

        # Obtener la sección de código
        codigo_seccion = pe.sections[0]

        # Obtener el código ensamblador de la sección
        codigo = codigo_seccion.get_data()

        # Analizar el código ensamblador
        informacion_codigo = "\n== Análisis de código ensamblador ==\n"
        for instruccion in md.disasm(codigo, base_address + codigo_seccion.VirtualAddress):
            informacion_codigo += f"{instruccion.address:08x} {instruccion.mnemonic} {instruccion.op_str}\n"
        messagebox.showinfo("Análisis de código ensamblador", informacion_codigo)

    except pefile.PEFormatError as e:
        messagebox.showerror("Error", f"Error al analizar el archivo PE: {e}")

def analizar_archivo(ruta_archivo, reglas):
    try:
        # Cargar las reglas YARA
        reglas_compiladas = yara.compile(source=reglas)

        # Abrir el archivo para su análisis
        with open(ruta_archivo, "rb") as archivo:
            contenido = archivo.read()

            # Ejecutar las reglas YARA en el archivo
            coincidencias = reglas_compiladas.match(data=contenido)

            # Verificar si se encontraron coincidencias
            if coincidencias:
                informacion_coincidencias = "\n== Coincidencias con las reglas YARA ==\n"
                for coincidencia in coincidencias:
                    informacion_coincidencias += f"Regla: {coincidencia.rule}\n"
                messagebox.showinfo("Coincidencias YARA", informacion_coincidencias)

            # Analizar ransomware (ejemplo)
            if "ransomware" in coincidencias:
                respuesta = messagebox.askyesno("Detección de Ransomware",
                                                "Se ha detectado una posible actividad de ransomware.\n"
                                                "¿Desea eliminar el archivo?")
                if respuesta:
                    eliminar_archivo(ruta_archivo)

    except yara.Error as e:
        messagebox.showerror("Error", f"Error al aplicar las reglas YARA: {e}")

def eliminar_archivo(ruta_archivo):
    try:
        os.remove(ruta_archivo)
        messagebox.showinfo("Eliminación exitosa", "El archivo ha sido eliminado exitosamente.")
    except Exception as e:
        messagebox.showerror("Error", f"Error al eliminar el archivo: {e}")

def ejecutar_en_sandbox(ruta_archivo):
    try:
        sandbox_dir = "sandbox"
        shutil.copy(ruta_archivo, sandbox_dir)

        sandbox_exe = os.path.join(sandbox_dir, os.path.basename(ruta_archivo))
        subprocess.Popen(sandbox_exe)

    except Exception as e:
        messagebox.showerror("Error", f"Error al ejecutar el archivo en el sandbox: {e}")

def abrir_archivo():
    ruta_archivo = filedialog.askopenfilename(filetypes=[("Archivos ejecutables", "*.exe")])
    if ruta_archivo:
        reglas_yara = filedialog.askopenfilename(filetypes=[("Archivos YARA", "*.yar")])
        if reglas_yara:
            analizar_archivo_pe(ruta_archivo)
            analizar_codigo_ensamblador(ruta_archivo)
            analizar_archivo(ruta_archivo, reglas_yara)
            ejecutar_en_sandbox(ruta_archivo)

# Crear la ventana principal
ventana = tk.Tk()
ventana.title("Ursus - Herramienta de análisis de malware")
ventana.geometry("400x200")

# Función para iniciar el análisis
def iniciar_analisis():
    ruta_archivo = archivo_entry.get()
    reglas_yara = reglas_entry.get()
    if ruta_archivo and reglas_yara:
        analizar_archivo_pe(ruta_archivo)
        analizar_codigo_ensamblador(ruta_archivo)
        analizar_archivo(ruta_archivo, reglas_yara)
        ejecutar_en_sandbox(ruta_archivo)

# Etiqueta y campo de entrada para el archivo
archivo_label = tk.Label(ventana, text="Archivo:")
archivo_label.pack()
archivo_entry = tk.Entry(ventana)
archivo_entry.pack(pady=5)

# Etiqueta y campo de entrada para las reglas YARA
reglas_label = tk.Label(ventana, text="Reglas YARA:")
reglas_label.pack()
reglas_entry = tk.Entry(ventana)
reglas_entry.pack(pady=5)

# Botón para iniciar el análisis
boton_analizar = tk.Button(ventana, text="Analizar", command=iniciar_analisis)
boton_analizar.pack(pady=10)

# Ejecutar el bucle principal de la ventana
ventana.mainloop()
