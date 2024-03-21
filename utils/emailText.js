const generateDynamicEmail = (firstName, link) => {

    return `
  

    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="utf-8"> <!-- utf-8 works for most cases -->
        <meta name="viewport" content="width=device-width"> <!-- Forcing initial-scale shouldn't be necessary -->
        <meta http-equiv="X-UA-Compatible" content="IE=edge"> <!-- Use the latest (edge) version of IE rendering engine -->
        <meta name="x-apple-disable-message-reformatting">  <!-- Disable auto-scale in iOS 10 Mail entirely -->
        <title></title> <!-- The title tag shows in email notifications, like Android 4.4. -->
        <link href="https://fonts.googleapis.com/css?family=Lato:300,400,700" rel="stylesheet">
    </head>
    <body style="margin: 0; padding: 0 !important; mso-line-height-rule: exactly; background-color: #f1f1f1;">
        <center style="width: 100%; background-color: #f1f1f1;">
        <div style="display: none; font-size: 1px;max-height: 0px; max-width: 0px; opacity: 0; overflow: hidden; mso-hide: all; font-family: sans-serif;">
            &zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;
        </div>
        <div style="max-width: 600px; margin: 0 auto;">
            <!-- BEGIN BODY -->
          <table align="center" role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="margin: auto;">
              <tr>
              <td valign="top" style="padding: 1em 2.5em 0 2.5em; background-color: #ffffff;">
                  <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%">
                      <tr>
                          <!-- <td style="text-align: center;">
                            <h1 style="margin: 0;"><a href="#" style="color: #30e3ca; font-size: 24px; font-weight: 700; font-family: 'Lato', sans-serif;">THE CURVE COHORT3</a></h1>
                          </td> -->
                      </tr>
                  </table>
              </td>
              </tr><!-- end tr -->
              <tr>
              <td valign="middle" style="padding: 3em 0 2em 0;">
              <img src="https://res.cloudinary.com/dx6qmw7w9/image/upload/v1705696901/EchoSphere_Blog_Logo_1_ruywpn.png" alt=""
              style="width: 200px; max-width: 300px; height: auto; margin: auto; display: block;">
              </td>
              </tr><!-- end tr -->
                    <tr>
              <td valign="middle" style="padding: 2em 0 4em 0;">
                <table>
                    <tr>
                        <td>
                            <div style="padding: 0 2.5em; text-align: center;">
                                <h2 style="font-family: 'Lato', sans-serif; color: rgba(0,0,0,.3); font-size: 40px; margin-bottom: 0; font-weight: 400;">Please verify your email</h2>
                                <h3 style="font-family: 'Lato', sans-serif; font-size: 24px; font-weight: 300;"> Welcome On Board , ${firstName},<br/>Click the button below to verify your account.</h3>
                                <p><a href=${link} class="btn btn-primary" style="padding: 10px 25px; display: inline-block; border-radius: 3px; background: #994caf; color: #ffffff; text-decoration: none; font-size: 30px; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; font-weight: 500;">Verify</a></p>
                                <!-- <h6 style="font-family: 'Lato', sans-serif; font-size: 18px; font-weight: 300;">This email expires in 5minutes</h6> -->
                            </div>
                        </td>
                    </tr>
                </table>
              </td>
              </tr><!-- end tr -->
          <!-- 1 Column Text + Button : END -->
          </table>
          <table align="center" role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="margin: auto;">
              <tr>
              <div style="margin: auto; display: flex; justify-content: center; align-items: center; ">
              <a href="https://echo-sphere-blog.onrender.com" target="_blank">
                  <div style="width: auto; height: 40px; object-fit: contain; margin: auto; display: flex;">
                      <img src="https://res.cloudinary.com/dx6qmw7w9/image/upload/v1705696901/EchoSphere_Blog_Logo_2-2_phvzmj.png" alt="">
                  </div>
              </a>
                  <ul style="font-family: Mona Sans, Helvetica Neue, Helvetica, Arial, sans-serif; Font-size: 15px; Font-weight: 600; Line-height: 20px; color: rgb(13, 12, 34); display: flex; flex-direction: row; justify-content: space-around; list-style-type: none; width: 400px;">
                      <li>For designers</li>
                      <li>Blog</li>
                      <li>About</li> 
                      <li>Support</li>
               </ul>
               <div style="width: 120px; height: 20px; object-fit: contain; margin: auto; display: flex; display: flex; flex-direction: row; justify-content: space-evenly; padding-left: 20px;">
                  <a href="https://twitter.com/your_username" target="_blank" style="height: 20px; object-fit: contain; margin: auto; display: flex; display: flex; flex-direction: row; justify-content: space-evenly;">
                      <img src="https://res.cloudinary.com/dx6qmw7w9/image/upload/v1705725720/twitter-icon_fdawvi.png" alt="twitter" >
                  </a>
                  <a href="https://facebook.com/your_username" target="_blank" style="height: 20px; object-fit: contain; margin: auto; display: flex; display: flex; flex-direction: row; justify-content: space-evenly;">
                      <img src="https://res.cloudinary.com/dx6qmw7w9/image/upload/v1705725721/350974_facebook_logo_icon_zoxrpw.png" alt="facebook" >
                  </a>
                  <a href="https://instagram.com/your_username" target="_blank" style="height: 20px; object-fit: contain; margin: auto; display: flex; display: flex; flex-direction: row; justify-content: space-evenly;">
                      <img src="https://res.cloudinary.com/dx6qmw7w9/image/upload/v1705725721/Instagram-PNGinstagram-icon-png_yf4g2j.png" alt="instagram" >
                  </a>
                  <a href="https://pinterest.com/your_username" target="_blank" style="height: 20px; object-fit: contain; margin: auto; display: flex; display: flex; flex-direction: row; justify-content: space-evenly;">
                      <img src="https://res.cloudinary.com/dx6qmw7w9/image/upload/v1705725720/pinterest-round-logo_lsfeqy.png" alt="pinterest"  >
                  </a>
               </div>
            </tr><!-- end: tr -->
            <tr>
              <td style="text-align: center; background-color: #fafafa;">
              © Copyright ${new Date().getFullYear()}. All rights reserved. EchoSphere Blog.<br/>
              </td>
            </tr>
          </table>
    
        </div>
      </center>
    </body>
    </html>
  
    `
}


module.exports = {generateDynamicEmail}