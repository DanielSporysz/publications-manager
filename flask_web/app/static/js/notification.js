window.onload = function() {
    sse();
};

function sse() {
    var source = new EventSource('/stream');
    var out = document.getElementById('out');
    source.onmessage = function(e) {
        out.innerHTML = out.innerHTML + '<div class ="notification">' +  e.data + '</div>';
    };
}