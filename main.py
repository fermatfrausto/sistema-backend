import hashlib
import os
import zipfile
import json
import re
import httpx  # Asegúrate de haber ejecutado 'pip install httpx'
from datetime import datetime
from fastapi import FastAPI, File, UploadFile, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="Sistema de Aseguramiento de Evidencia Digital (.EVID)",
    description="Backend forense con sellado de tiempo internacional e inmutabilidad",
    version="2.2.1"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

REPOSITORIO_DIR = "repositorio_forense"
os.makedirs(REPOSITORIO_DIR, exist_ok=True)

def limpiar_nombre_archivo(nombre: str) -> str:
    nombre_limpio = re.sub(r'[^a-zA-Z0-9_\-]', '_', nombre)
    return re.sub(r'_+', '_', nombre_limpio).strip('_')

# ------------------------------------------------------------------------------
# SERVIDOR DE TIEMPO INTERNACIONAL
# ------------------------------------------------------------------------------
def obtener_fecha_hora_internacional() -> tuple:
    """ Consulta servidores de tiempo globales. Devuelve (fecha_hora, fuente) """
    try:
        url_tiempo = "https://timeapi.world"
        response = httpx.get(url_tiempo, timeout=3.0)
        
        if response.status_code == 200:
            datos_tiempo = response.json()
            dt_raw = datos_tiempo["datetime"]
            dt_objeto = datetime.fromisoformat(dt_raw)
            return dt_objeto.strftime("%Y-%m-%d %H:%M:%S"), "Servidor de Tiempo Atómico Internacional (TimeAPI)"
    except Exception:
        pass
    
    # Fallback si no hay internet en el laboratorio
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "Servidor Local Aislado (Respaldo Forense)"

# ------------------------------------------------------------------------------

@app.post("/subir-evidencia")
async def subir_evidencia(
    id_caso: str = Form(...),
    perito: str = Form(...),
    hash_origen: str = Form(...),
    imagen: UploadFile = File(...)
):
    try:
        contenido_imagen = await imagen.read()
        
        sha256_hash = hashlib.sha256(contenido_imagen).hexdigest()
        if sha256_hash != hash_origen:
            raise HTTPException(
                status_code=400, 
                detail="¡ALERTA! El hash calculado no coincide con el de origen. Cadena de custodia rota."
            )
        
        # Extraer hora y fuente oficial
        fecha_hora_registro, fuente_tiempo = obtener_fecha_hora_internacional()
        
        manifiesto_datos = {
            "sistema_registro": "Plataforma de Custodia Carlos v2.2.1",
            "estatus_evidencia": "Asegurada e Íntegra",
            "fuente_del_tiempo": fuente_tiempo,
            "detalles_caso": {
                "id_caso_expediente": id_caso,
                "perito_recolector": perito,
                "fecha_hora_ingreso": fecha_hora_registro
            },
            "archivo_datos": {
                "nombre_original": imagen.filename,
                "hash_sha256_verificado": sha256_hash
            },
            "trazabilidad": [
                {
                    "paso": 1,
                    "evento": "Generación de hash local y transmisión desde dispositivo de origen",
                    "responsable": perito,
                    "timestamp": fecha_hora_registro
                },
                {
                    "paso": 2,
                    "evento": "Validación criptográfica e ingreso al repositorio forense",
                    "responsable": "Core Python Backend",
                    "timestamp": fecha_hora_registro
                }
            ],
            "nota_legal": "Este archivo permanece inalterado en su estado nativo de bytes y queda en espera de su procesamiento por el motor de análisis forense digital."
        }
        
        id_caso_seguro = limpiar_nombre_archivo(id_caso)
        nombre_contenedor = f"{id_caso_seguro}_{sha256_hash[:10].upper()}.evid"
        ruta_contenedor_final = os.path.join(REPOSITORIO_DIR, nombre_contenedor)
        
        with zipfile.ZipFile(ruta_contenedor_final, "w", zipfile.ZIP_DEFLATED) as archivo_evid:
            archivo_evid.writestr(f"evidencia_{imagen.filename}", contenido_imagen)
            archivo_evid.writestr("acta_custodia.json", json.dumps(manifiesto_datos, indent=4))
        
        return {
            "status": "Éxito",
            "datos_custodia": {
                "id_caso": id_caso,
                "perito": perito,
                "hash_verificado_sha256": sha256_hash,
                "fecha_hora": fecha_hora_registro,
                "fuente_tiempo": fuente_tiempo, # Enviado al HTML
                "contenedor_generado": nombre_contenedor
            }
        }
        
    except Exception as e:
        if isinstance(e, HTTPException): raise e
        raise HTTPException(status_code=500, detail=f"Error crítico en el servidor forense: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
