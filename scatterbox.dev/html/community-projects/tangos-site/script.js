// Define the sendMessage function
function sendMessage() {
    var name = document.getElementById("name").value;
    var message = document.getElementById("message").value;
    var webhook = "https://discord.com/api/webhooks/1262467650974515292/ypwkYuXluxWEv3FzN-6ESyrtFvGUEp-4Uh7XlV2Prr6iJi67aqfw_qxE1SBaRKb_Ta6N";  // Replace with your actual webhook URL
    var content = `senders name: ${name} \nmessage: ${message}`;
    
    // Create the JSON payload
    var params = {
        content: content
    };
    
    console.log('Payload:', JSON.stringify(params));  // Debugging: Log the payload

    var request = new XMLHttpRequest();
    request.open("POST", webhook, true);
    request.setRequestHeader('Content-type', 'application/json');
    
    request.onreadystatechange = function() {
        if (request.readyState === 4) {
            console.log('Response:', request.responseText);  // Debugging: Log the response
            if (request.status === 204) {
                alert('Message sent successfully!');
            } else {
                alert('Error sending message: ' + request.status + ' ' + request.statusText);
            }
        }
    };
    
    // Send the JSON payload
    request.send(JSON.stringify(params));
}

// Add an event listener to the button
document.getElementById("send").addEventListener("click", sendMessage);