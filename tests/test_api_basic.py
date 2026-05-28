def test_list_scripts_returns_json(client):

    response = client.get("/api/scripts")

    assert response.status_code == 200
    data = response.get_json()
    assert isinstance(data, dict)

    for category, scripts in data.items():
        assert isinstance(category, str)
        assert isinstance(scripts, list)
        for script in scripts:
            assert isinstance(script, dict)
            assert "file" in script
            assert "relative_path" in script
            assert "favorite" in script
            assert "locked" in script


def test_workspace_get_returns_success(client):

    response = client.get("/api/workspace")

    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert "workspace" in data


def test_script_run_with_arguments(client):
    """Test that arguments are correctly passed to scripts"""
    import os
    import json
    
    # Create a test script that echoes its arguments
    script_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'scripts')
    test_script_path = os.path.join(script_dir, 'test_args.sh')
    
    # Create test script directory if it doesn't exist
    os.makedirs(script_dir, exist_ok=True)
    
    # Write a test script that outputs its arguments
    with open(test_script_path, 'w') as f:
        f.write('#!/bin/bash\n')
        f.write('echo "Arguments: $@"\n')
        f.write('for arg in "$@"; do\n')
        f.write('  echo "Arg: $arg"\n')
        f.write('done\n')
        f.write('exit 0\n')
    
    os.chmod(test_script_path, 0o755)
    
    try:
        # Run script with arguments
        response = client.post(
            "/api/scripts/run",
            json={
                "path": "test_args.sh",
                "password": "",
                "arguments": ["--verbose", "--output", "test.txt"]
            }
        )
        
        assert response.status_code == 200
        
        # Verify the response is an SSE stream
        assert response.content_type == "text/event-stream"
        
        # Collect all SSE events
        events = []
        for line in response.data.decode('utf-8').split('\n\n'):
            if line.startswith('data: '):
                try:
                    events.append(json.loads(line[6:]))
                except:
                    pass
        
        # Verify that started and metrics events were received
        assert any(e.get('type') == 'started' for e in events)
        assert any(e.get('type') == 'metrics' for e in events)
        
    finally:
        # Clean up test script
        if os.path.exists(test_script_path):
            os.remove(test_script_path)


def test_script_run_with_empty_arguments(client):
    """Test that scripts run correctly with empty arguments list"""
    import os
    import json
    
    script_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'scripts')
    test_script_path = os.path.join(script_dir, 'test_noargs.sh')
    
    os.makedirs(script_dir, exist_ok=True)
    
    with open(test_script_path, 'w') as f:
        f.write('#!/bin/bash\n')
        f.write('echo "Running without arguments"\n')
        f.write('exit 0\n')
    
    os.chmod(test_script_path, 0o755)
    
    try:
        # Run script with empty arguments list
        response = client.post(
            "/api/scripts/run",
            json={
                "path": "test_noargs.sh",
                "password": "",
                "arguments": []
            }
        )
        
        assert response.status_code == 200
        assert response.content_type == "text/event-stream"
        
    finally:
        if os.path.exists(test_script_path):
            os.remove(test_script_path)


def test_script_run_without_arguments_field(client):
    """Test backward compatibility - scripts run without arguments field"""
    import os
    
    script_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'scripts')
    test_script_path = os.path.join(script_dir, 'test_compat.sh')
    
    os.makedirs(script_dir, exist_ok=True)
    
    with open(test_script_path, 'w') as f:
        f.write('#!/bin/bash\n')
        f.write('echo "Backward compatible"\n')
        f.write('exit 0\n')
    
    os.chmod(test_script_path, 0o755)
    
    try:
        # Run script without arguments field (backward compatibility)
        response = client.post(
            "/api/scripts/run",
            json={
                "path": "test_compat.sh",
                "password": ""
                # No "arguments" field
            }
        )
        
        assert response.status_code == 200
        assert response.content_type == "text/event-stream"
        
    finally:
        if os.path.exists(test_script_path):
            os.remove(test_script_path)

