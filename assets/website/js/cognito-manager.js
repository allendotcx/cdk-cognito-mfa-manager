
const manager_url = "https://eb0kmrljwe.execute-api.eu-west-2.amazonaws.com/dev/cognitomanager";
const qrcode_url = "https://ck9gthp49c.execute-api.eu-west-2.amazonaws.com/dev/qrCodeResource";

async function retrieveQrCode({ otpauth }) {
  const url = qrcode_url;
  const plainFormData = {
    type: 'qr',
    height: 200,
    width: 200,
    message: otpauth,
  };

  const formDataJsonString = JSON.stringify(plainFormData);
  const fetchOptions = {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
      'authorization': 'Bearer ' + tokens.access_token
    },
    body: formDataJsonString,
  };
  const response = await fetch(url, fetchOptions);
  if (!response.ok) {
    const errorMessage = await response.text();
    throw new Error(errorMessage);
  }
  return response.json();
}

async function postFormDataAsJson({ url, formData }) {
  const plainFormData = Object.fromEntries(formData.entries());
  plainFormData['username'] = plainFormData['email'];
  const formDataJsonString = JSON.stringify(plainFormData);

  const fetchOptions = {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
      'authorization': 'Bearer ' + tokens.access_token
    },
    body: formDataJsonString,
  };

  const response = await fetch(url, fetchOptions);
  if (!response.ok) {
    const errorMessage = await response.text();
    throw new Error(errorMessage);
  }
  return response.json();

}

/**
* Event handler for a form submit event.
* @see https://developer.mozilla.org/en-US/docs/Web/API/HTMLFormElement/submit_event
* @param {SubmitEvent} event
*/
async function handleFormSubmit(event) {
  document.getElementById("qrcode").style.visibility = "hidden";
  document.getElementById("output").textContext = "Working...";

  event.preventDefault();
  const form = event.currentTarget;
  // const url = form.action;
  const url = manager_url;
  try {
    const formData = new FormData(form);
    const responseData = await postFormDataAsJson({ url, formData });
    console.log( responseData );

    status_code = responseData['status']
    data_body = responseData['body'];
    output = 'status: '+ status_code + '\n' + JSON.stringify(JSON.parse(data_body),null,4);
    document.getElementById('output').textContent = output

    mfa_token = JSON.parse(data_body).mfa_token;
    list_users();

  } catch (error) {
    console.error(error);
  }

  if(mfa_token){
    otpauth = 'otpauth://totp/' + 'demo1_' + form.username.value + '?secret=' + mfa_token;
    document.getElementById('otpauth').textContent = otpauth;

    try {
      const formData = new FormData(form);
      const responseData = await retrieveQrCode({ otpauth });
      const imageUrl = 'data:image/png;base64,' + responseData;
      console.log({ imageUrl});
      document.getElementById('qrcode').src = imageUrl;
      document.getElementById("qrcode").style.visibility = "visible";
    } catch (error) {
      console.error(error);
    }
  } else {
    document.getElementById('otpauth').textContent = 'otpauth not set';
  }
}

const myForm = document.getElementById("myForm");
myForm.addEventListener("submit", handleFormSubmit);

// List User Accounts
async function list_users() {
  document.getElementById('users_message').textContent = "Users Loading...";
  var xhr = new XMLHttpRequest();
  xhr.open("POST", manager_url, true);
  xhr.setRequestHeader('Content-Type', 'application/json');
  xhr.send(JSON.stringify({
    action: 'get_all_users'
  }));
  xhr.onload = function() {
    //console.log("HELLO")
    //console.log(this.responseText);
    var data = JSON.parse(this.responseText);
    //console.log(data);
    document.getElementById('list_users').textContent = JSON.stringify(JSON.parse(data['body']), null, 4);
  }
  document.getElementById('users_message').textContent = "Users";
}
//    addEventListener('load', (event) => { list_users() });
