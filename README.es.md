# ScopeLens

**Tu agente necesita leer código. ¿Por qué su integración también puede modificarlo?**

Una herramienta local para comparar permisos de GitHub con una tarea concreta y revisar configuraciones MCP. Genera informes HTML y JSON con evidencias, limitaciones y recomendaciones. Alfa 0.1.0, Python 3.10+, sin dependencias de ejecución.

## Pruébalo

```bash
git clone https://github.com/pedronavarro-labs/scopelens.git
cd scopelens
python scopelens.py scan examples/overprivileged.json --task read-code --repo demo/docs --mcp examples/mcp.json --output artifacts/before
python scopelens.py scan examples/scoped.json --task read-code --repo demo/docs --output artifacts/after
```

Abre los archivos `report.html` de ambas carpetas. También puedes abrir `demo/index.html` tras descargar el repositorio. Los ejemplos son sintéticos.

- `read-code`: leer contenido de un repositorio privado.
- `review-pr`: leer código y publicar una revisión de pull request.
- `create-issue`: crear una incidencia básica.

El informe diferencia permisos declarados, permisos de instalación obtenidos de la API y acceso efectivo desconocido. **Cero alertas no significa que un agente sea seguro.** Son perfiles acotados, no mínimos universales.

La revisión MCP no ejecuta servidores ni envía credenciales. Omite del informe sus comandos, argumentos, URL, nombres y valores de configuración. Los identificadores de repositorios GitHub sí aparecen: revisa el informe antes de compartirlo.

El recolector opcional requiere un token de usuario de una GitHub App en `SCOPELENS_GITHUB_TOKEN`. No acepta PATs ni el token de GitHub Actions. Solo consulta las instalaciones visibles para esa App y ese usuario. Sus pruebas usan respuestas simuladas; la interoperabilidad autenticada real sigue pendiente.

`diff` compara dos informes de la misma tarea y devuelve 1 ante cambios de alcance o evidencia, incluidas reducciones. No cambia permisos ni certifica seguridad.

Consulta [README completo](README.md), [modelo de evidencia](EVIDENCE.md) y [seguridad](SECURITY.md).
