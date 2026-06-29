# Mini SIEM Project

This is a hybrid security project featuring an x86 Assembly backend (Mini_SIEM) for log parsing and threat scoring, and a modern Python (Streamlit) frontend dashboard for analytics and AI-powered incident reporting.

## 📁 Included Files
To run this project, make sure you have the following files in the same folder:
- `Mini_SIEM.asm` - The source code for the Assembly backend.
- `Mini_SIEM.exe` - The compiled backend engine (must be in the root directory).
- `app.py` - The Python frontend dashboard.
- `logs file.txt` - Sample security event logs for testing.

## 🛠️ Prerequisites
Before running the project, you need to install the required Python libraries.
Open your terminal (PowerShell or Command Prompt) and run:
```bash
pip install streamlit google-genai
```

## 🚀 How to Run the Dashboard

1. **Set up your API Key:**
   To use the AI Incident Report feature, you need a free Google Gemini API key. 
   Set the environment variable in your terminal before running the app.
   
   **For Windows PowerShell:**
   ```powershell
   $env:GEMINI_API_KEY="AQAb8RN6JbSPb8A4u4kWiY0OUwslZdMa1-7f3w2bfU4W1NW15JVQ"
   ```
   **For Windows Command Prompt (cmd):**
   ```cmd
   set GEMINI_API_KEY="AQAb8RN6JbSPb8A4u4kWiY0OUwslZdMa1-7f3w2bfU4W1NW15JVQ"
   ```

2. **Launch the Dashboard:**
   In the same terminal where you set the API key, run the following command:
   ```bash
   streamlit run app.py
   ```

3. **Using the App:**
   - The dashboard will open in your web browser (usually at `http://localhost:8501`).
   - Upload the sample `logs file.txt`.
   - Click **"Run Threat Analysis"**.
   - The Assembly backend will process the logs, and the dashboard will display the UEBA alerts, SOAR actions, and stream a live AI Incident Report!

## ⚙️ Compiling the Backend (Optional)
If you make changes to `Mini_SIEM.asm` and need to recompile it, you must have MASM and the Irvine32 library installed at `C:\irvine`. Use the Visual Studio Developer Command Prompt:
```cmd
ml.exe /c /Zd /coff /I"C:\irvine" Mini_SIEM.asm
link.exe /SUBSYSTEM:CONSOLE /LIBPATH:"C:\irvine" Mini_SIEM.obj Irvine32.lib kernel32.lib user32.lib
```
