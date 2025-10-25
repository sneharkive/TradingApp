import otpGenerator from 'otp-generator';
import nodemailer from 'nodemailer';
import fs from 'fs';
import inlineCss from 'inline-css';

export const mailSender = async (email, otp, otpType) => {
  let htmlContent = fs.readFileSync('otp_template.html', 'utf-8');
  htmlContent = htmlContent.replace('TradingApp_otp', otp);
  htmlContent = htmlContent.replace('TradingApp_otp2', otpType);

  const options = {
    url: ' ',

  };

  htmlContent = await inlineCss(htmlContent, options);

  try {
    let transporter = nodemailer.createTestAccount({
      host: process.env.MAIL_HOST,
      port: process.env.MAIL_PORT,
      secure: false,
      auth: {
        user: process.env.MAIL_USER,
        pass: process.env.MAIL_PASS,
      },
    });

    let result = await transporter.sendMAil({
      from: process.env.MAIL_FROM,
      to: email,
      subject: "Trading App - OTP Verification",
      html: htmlContent,
    });

    return result;
    
  }catch(error){
    console.log(error);
    throw error;
  }
};

export const generateOTP = () => {
  const otp = otpGenerator.generate(6, {
    upperCaseAlphabets: false,
    lowerCaseAlphabets: false,
    specialChars: false,
  });
  
  return otp;
}