import pefile
import struct
from typing import Dict, Any

class PEAnalyzer:
    """PE (Portable Executable) file analyzer"""
    
    def analyze(self, file_bytes: bytes) -> Dict[str, Any]:
        """Analyze PE file structure"""
        result = {
            "is_pe": False,
            "sections": 0,
            "imports": 0,
            "exports": 0,
            "suspicious_sections": False,
            "suspicious_imports": []
        }
        
        # Check if it's a PE file
        if len(file_bytes) < 64 or file_bytes[:2] != b'MZ':
            return result
        
        try:
            pe = pefile.PE(data=file_bytes)
            result["is_pe"] = True
            
            # Basic info
            result["sections"] = len(pe.sections)
            
            # Imports
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                result["imports"] = len(pe.DIRECTORY_ENTRY_IMPORT)
                
                # Check for suspicious imports
                suspicious_apis = [
                    "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory",
                    "LoadLibraryA", "GetProcAddress", "URLDownloadToFile",
                    "CreateProcess", "ShellExecute", "WinExec"
                ]
                
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            imp_name = imp.name.decode('utf-8', errors='ignore')
                            if any(api in imp_name for api in suspicious_apis):
                                result["suspicious_imports"].append(imp_name)
            
            # Exports
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                result["exports"] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
            
            # Check section names for packers
            packer_sections = ['.packed', '.upx', '.crypt', '.aspack', '.themida']
            for section in pe.sections:
                section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                if any(packer in section_name.lower() for packer in packer_sections):
                    result["suspicious_sections"] = True
                    break
            
            pe.close()
            
        except Exception as e:
            result["error"] = str(e)
        
        return result