let url = window.location.href;

fetch("http://127.0.0.1:5000/predict", {
    method: "POST",
    headers: {
        "Content-Type": "application/json"
    },
    body: JSON.stringify({url: url})
})
.then(response => response.json())
.then(data => {

    if(data.result === "Phishing Website"){
        alert("⚠ Warning! This website may be a phishing site.");
    }
});