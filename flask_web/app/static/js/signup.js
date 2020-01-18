var username;
var password;
var rePassword;
var button;

window.onload = function() {
    findElements();
    addListeners();
};

function findElements(){
    username = document.getElementById('usernameInput')
    password = document.getElementById('passwordInput')
    rePassword = document.getElementById('rePasswordInput')
    button = document.getElementById('button')
}

function addListeners(){
    button.type = "button"
    button.addEventListener("click", function (event) {
        if (!formIsReady()) {
            event.preventDefault();
        } else {
            document.getElementById('regForm').submit();
        }
    }, false);

    // username 
    username.addEventListener("input", function(event){
        clearErrorMessage('usernameDiv')
    }, false);
    const debouncedLoginCheck = debounced(700, checkUsername);
    username.addEventListener("input", debouncedLoginCheck);
    const debouncedLoginAvailability = debounced(1000, checkUsernameAvailability);
    username.addEventListener("input", debouncedLoginAvailability);

    // password
    password.addEventListener("input", function(event){
        clearErrorMessage('passwordDiv')
    }, false);
    const debouncedPassCheck = debounced(1000, checkPassword);
    password.addEventListener("input", debouncedPassCheck);

    // repassword
    rePassword.addEventListener("input", function(event){
        clearErrorMessage('rePasswordDiv')
    }, false);
    const debouncedRePassCheck = debounced(1000, checkRePassword);
    rePassword.addEventListener("input", debouncedRePassCheck);
}

function clearErrorMessage(divTargetName){
    const parent = document.getElementById(divTargetName);

    if(parent.lastChild.nodeName == "DIV"){
        parent.removeChild(parent.lastChild);
    }
}

function insertErrorMessage(message, divTargetName){
    const parent = document.getElementById(divTargetName);

    clearErrorMessage(divTargetName);

    var errorDiv = document.createElement("div"); 
    errorDiv.className = "error"
    const errorMessage = document.createTextNode(message)
    errorDiv.appendChild(errorMessage);  
    parent.appendChild(errorDiv);
}

function formIsReady(){
    // Check if the fields are filled
    if(username.value.length == 0){
        clearErrorMessage("usernameDiv");
        insertErrorMessage("Please fill in this field!", "usernameDiv");
        return false
    } else if (password.value.length == 0){
        clearErrorMessage("passwordDiv");
        insertErrorMessage("Please fill in this field!", "passwordDiv");
        return false
    } else if (rePassword.value.length == 0){
        clearErrorMessage("rePasswordDiv");
        insertErrorMessage("Please fill in this field!", "rePasswordDiv");
        return false
    }

    checkUsername();
    checkPassword();
    checkRePassword();
    
    //Check if they are filled correctly
    const errors = document.getElementsByClassName("error");
    if (errors.length != 0){
        return false;
    }
    return true;
}

function debounced(delay, fn) {
    let timerId;
    return function (...args) {
        if (timerId) {
            clearTimeout(timerId);
        }
        timerId = setTimeout(() => {
            fn(...args);
            timerId = null;
        }, delay);
    }
}

function checkUsername(){
    value = username.value;
    if(value.length === 0) {
        return;
    } else if(!/^[a-zA-Z0-9]+$/.test(value)){
        insertErrorMessage("Do not use any special characters.", "usernameDiv")
    } else if(value.length < 3){
        insertErrorMessage("Username should be at least 3 characters long.", "usernameDiv")
    } else if(value.length > 20){
        insertErrorMessage("Username too long! Stay between 3-20 characters.", "usernameDiv")
    }
}

function checkUsernameAvailability() {
    if(username.value === ""){
        return;
    }

    let theUrl = "https://web.company.com/user/" + username.value;

    let xmlHttp = new XMLHttpRequest();
    xmlHttp.open("GET", theUrl, true); // true for asynchronous
    xmlHttp.onloadend = function() {
        if(xmlHttp.status !== 404){
            clearErrorMessage("usernameDiv");
            insertErrorMessage("This username is already taken!", "usernameDiv");
        }
    };
    xmlHttp.send(null);
}

function checkPassword(){
    value = password.value;
    if(value.length === 0) {
        return;
    } else if(value.length < 8){
        insertErrorMessage("Password should be at least 8 characters long.", "passwordDiv")
    } else if(value.length > 50){
        insertErrorMessage("Password too long! Stay between 8-50 characters.", "passwordDiv")
    }

    checkRePassword();
}

function checkRePassword(){
    value = rePassword.value;
    if(value.length === 0) {
        return;
    } else if(value !== password.value){
        insertErrorMessage("Passwords do not match.", "rePasswordDiv");
    }
}