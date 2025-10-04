"""
Ollama Client Library for AI-Driven SIEM System

This module provides integration with Ollama for local AI model inference.
It supports both local Ollama installations and fallback to API-based models.
"""

import requests
import json
import logging
from typing import Optional, Dict, Any

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class OllamaClient:
    """
    Client for interacting with Ollama AI models locally.
    """
    
    def __init__(self, base_url: str = "http://localhost:11434", model: str = "llama3.2"):
        """
        Initialize the Ollama client.
        
        Args:
            base_url (str): Base URL for the Ollama API
            model (str): Default model to use for inference
        """
        self.base_url = base_url.rstrip('/')
        self.model = model
        self.session = requests.Session()
        
    def is_available(self) -> bool:
        """
        Check if Ollama service is available.
        
        Returns:
            bool: True if Ollama is available, False otherwise
        """
        try:
            response = self.session.get(f"{self.base_url}/api/tags", timeout=5)
            return response.status_code == 200
        except requests.RequestException as e:
            logger.warning(f"Ollama service not available: {e}")
            return False
    
    def list_models(self) -> Optional[Dict[str, Any]]:
        """
        List available models in Ollama.
        
        Returns:
            Optional[Dict]: List of available models or None if error
        """
        try:
            response = self.session.get(f"{self.base_url}/api/tags")
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(f"Error listing models: {e}")
            return None
    
    def generate(self, prompt: str, model: Optional[str] = None, stream: bool = False) -> str:
        """
        Generate response from Ollama model.
        
        Args:
            prompt (str): Input prompt for the model
            model (Optional[str]): Model to use (defaults to self.model)
            stream (bool): Whether to stream the response
            
        Returns:
            str: Generated response text
        """
        model_name = model or self.model
        
        payload = {
            "model": model_name,
            "prompt": prompt,
            "stream": stream
        }
        
        try:
            response = self.session.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=30
            )
            response.raise_for_status()
            
            if stream:
                # Handle streaming response
                result = ""
                for line in response.iter_lines():
                    if line:
                        data = json.loads(line.decode('utf-8'))
                        if 'response' in data:
                            result += data['response']
                        if data.get('done', False):
                            break
                return result
            else:
                # Handle single response
                data = response.json()
                return data.get('response', 'No response generated')
                
        except requests.RequestException as e:
            logger.error(f"Error generating response: {e}")
            return f"Error: {str(e)}"
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing response: {e}")
            return "Error: Unable to parse response"
    
    def chat(self, messages: list, model: Optional[str] = None) -> str:
        """
        Chat with Ollama model using conversation format.
        
        Args:
            messages (list): List of message dictionaries with 'role' and 'content'
            model (Optional[str]): Model to use (defaults to self.model)
            
        Returns:
            str: Generated response text
        """
        model_name = model or self.model
        
        payload = {
            "model": model_name,
            "messages": messages,
            "stream": False
        }
        
        try:
            response = self.session.post(
                f"{self.base_url}/api/chat",
                json=payload,
                timeout=30
            )
            response.raise_for_status()
            
            data = response.json()
            return data.get('message', {}).get('content', 'No response generated')
            
        except requests.RequestException as e:
            logger.error(f"Error in chat: {e}")
            return f"Error: {str(e)}"
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing chat response: {e}")
            return "Error: Unable to parse response"
    
    def pull_model(self, model_name: str) -> bool:
        """
        Pull a model from Ollama registry.
        
        Args:
            model_name (str): Name of the model to pull
            
        Returns:
            bool: True if successful, False otherwise
        """
        payload = {"name": model_name}
        
        try:
            response = self.session.post(
                f"{self.base_url}/api/pull",
                json=payload,
                timeout=300  # 5 minutes timeout for model download
            )
            response.raise_for_status()
            
            logger.info(f"Successfully pulled model: {model_name}")
            return True
            
        except requests.RequestException as e:
            logger.error(f"Error pulling model {model_name}: {e}")
            return False
    
    def analyze_security_event(self, event_data: Dict[str, Any]) -> str:
        """
        Analyze security event data using AI.
        
        Args:
            event_data (Dict): Security event information
            
        Returns:
            str: AI analysis of the security event
        """
        prompt = f"""
        Analyze the following security event and provide a brief assessment:
        
        Event Data: {json.dumps(event_data, indent=2)}
        
        Please provide:
        1. Threat level (Low/Medium/High/Critical)
        2. Brief explanation of the potential threat
        3. Recommended action
        
        Keep the response concise and actionable.
        """
        
        return self.generate(prompt)
    
    def generate_alert_summary(self, system_metrics: Dict[str, Any], logs: list, network_data: list) -> str:
        """
        Generate a summary of system status and potential alerts.
        
        Args:
            system_metrics (Dict): Current system metrics
            logs (list): Recent log entries
            network_data (list): Recent network activity
            
        Returns:
            str: AI-generated summary and alerts
        """
        prompt = f"""
        Analyze the following system data and provide a brief security status summary:
        
        System Metrics: {json.dumps(system_metrics, indent=2)}
        Recent Logs: {logs[:5]}  # Last 5 logs
        Network Activity: {network_data[:5]}  # Last 5 network events
        
        Provide a concise security status report focusing on:
        1. Overall system health
        2. Any suspicious activities
        3. Immediate recommendations
        
        Keep response under 100 words.
        """
        
        return self.generate(prompt)

# Singleton instance for global use
_ollama_client = None

def get_ollama_client() -> OllamaClient:
    """
    Get singleton Ollama client instance.
    
    Returns:
        OllamaClient: Configured Ollama client
    """
    global _ollama_client
    if _ollama_client is None:
        _ollama_client = OllamaClient()
    return _ollama_client

# Convenience functions
def analyze_with_ollama(prompt: str) -> str:
    """
    Convenience function to analyze data with Ollama.
    
    Args:
        prompt (str): Analysis prompt
        
    Returns:
        str: AI analysis result
    """
    client = get_ollama_client()
    if client.is_available():
        return client.generate(prompt)
    else:
        return "Ollama service is not available. Please ensure Ollama is running."

def chat_with_ollama(messages: list) -> str:
    """
    Convenience function for chat with Ollama.
    
    Args:
        messages (list): Chat messages
        
    Returns:
        str: AI chat response
    """
    client = get_ollama_client()
    if client.is_available():
        return client.chat(messages)
    else:
        return "Ollama service is not available. Please ensure Ollama is running."