import re
import base64
import json
import requests
import os

def convert_mermaid_to_images(input_file, output_file):
    with open(input_file, 'r') as f:
        content = f.read()

    # Regex to find mermaid blocks
    mermaid_pattern = re.compile(r'```mermaid\n(.*?)```', re.DOTALL)
    
    counter = 1
    
    def replace_mermaid(match):
        nonlocal counter
        mermaid_code = match.group(1)
        
        # Prepare JSON for mermaid.ink
        state = {
            "code": mermaid_code,
            "mermaid": {"theme": "default"}
        }
        json_state = json.dumps(state)
        encoded_state = base64.urlsafe_b64encode(json_state.encode('utf-8')).decode('utf-8')
        
        image_url = f"https://mermaid.ink/img/{encoded_state}"
        image_filename = f"mermaid_diagram_{counter}.png"
        
        print(f"Processing diagram {counter}...")
        
        import time
        for attempt in range(3):
            try:
                print(f"  Attempt {attempt+1} downloading from {image_url[:50]}...")
                response = requests.get(image_url, timeout=10)
                if response.status_code == 200:
                    with open(image_filename, 'wb') as img_file:
                        img_file.write(response.content)
                    replacement = f"![Diagram {counter}]({image_filename})"
                    counter += 1
                    time.sleep(2) # Be nice to the server
                    return replacement
                else:
                    print(f"  Failed status {response.status_code}")
                    time.sleep(2)
            except Exception as e:
                print(f"  Error: {e}")
                time.sleep(2)
        
        print(f"Giving up on diagram {counter}")
        counter += 1 # Increment anyway to keep numbering consistent if we skip
        return match.group(0)

    new_content = mermaid_pattern.sub(replace_mermaid, content)
    
    with open(output_file, 'w') as f:
        f.write(new_content)

if __name__ == "__main__":
    convert_mermaid_to_images('read.md', 'read_with_images.md')
