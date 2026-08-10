"""
FastAPI-side AI agent using Groq.
"""

import os
import sys
import re
from pathlib import Path

from dotenv import load_dotenv

# --------------------------------------------------
# Load .env
# --------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

# --------------------------------------------------
# Make project importable
# --------------------------------------------------
sys.path.insert(0, str(BASE_DIR))

# --------------------------------------------------
# Groq
# --------------------------------------------------
try:
    from groq import Groq
    GROQ_OK = True
except ImportError:
    GROQ_OK = False

# --------------------------------------------------
# Detection tools
# --------------------------------------------------
try:
    from detection.agent_tools import (
        check_ports,
        check_services,
        scan_network,
        ping_device,
        detect_unknown_devices,
        detect_unusual_ports,
    )

    TOOLS_OK = True

except ImportError:
    TOOLS_OK = False

# --------------------------------------------------
# Environment
# --------------------------------------------------
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

SYSTEM_PROMPT = """
You are an AI Network Security Assistant for an IDPS.

Responsibilities:
- Explain network events clearly.
- Help users understand alerts.
- Recommend security improvements.
- Keep responses concise.
- Use plain text only.
"""

# --------------------------------------------------
# Tool detection
# --------------------------------------------------
def _detect_tool(user_input: str):
    ui = user_input.lower()

    ports = re.findall(r"\b\d{2,5}\b", ui)

    if "port" in ui and ports:
        return "check_ports", [int(p) for p in ports]

    if "service" in ui:
        part = ui.split("service", 1)[1]
        services = [s.strip() for s in re.split(r"[,\s]+", part) if s.strip()]
        return "check_services", services[:5]

    match = re.search(r"ping (\d+\.\d+\.\d+\.\d+)", ui)

    if match:
        return "ping_device", match.group(1)

    if any(word in ui for word in ["scan", "network", "devices"]):
        return "scan_network", None

    if any(word in ui for word in ["anomaly", "anomalies", "threat", "unusual"]):
        return "detect_anomalies", None

    return None, None


# --------------------------------------------------
# Main AI Function
# --------------------------------------------------
def get_ai_response(user_input: str) -> str:

    if not GROQ_OK:
        return "Groq package is not installed."

    if not GROQ_API_KEY:
        return "GROQ_API_KEY was not found. Check your .env file."

    client = Groq(api_key=GROQ_API_KEY)

    tool, param = _detect_tool(user_input)

    tool_result = ""

    if TOOLS_OK and tool:

        try:

            if tool == "check_ports":
                tool_result = check_ports(param)

            elif tool == "check_services":
                tool_result = check_services(param)

            elif tool == "scan_network":
                tool_result = scan_network()

            elif tool == "ping_device":
                tool_result = ping_device(param)

            elif tool == "detect_anomalies":
                tool_result = (
                    f"{detect_unknown_devices()}\n"
                    f"{detect_unusual_ports()}"
                )

        except Exception as e:
            tool_result = f"Tool error: {e}"

    prompt = user_input

    if tool_result:
        prompt += f"\n\nTool Output:\n{tool_result}"

    try:

        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {
                    "role": "system",
                    "content": SYSTEM_PROMPT,
                },
                {
                    "role": "user",
                    "content": prompt,
                },
            ],
            max_tokens=512,
        )

        return response.choices[0].message.content.strip()

    except Exception as e:
        return f"Groq Error: {e}"
