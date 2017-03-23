

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import com.ecs.asaksa.client.api.KycProcessor;
import com.ecs.asaksa.client.api.OtpProcessor;
import com.ecs.asaksa.gateway.AsaOtpResponse;
import com.ecs.asaksa.gateway.KsaKycResponse;

import in.gov.uidai.auth.aua.helper.DigitalSigner;
import in.gov.uidai.auth.aua.helper.SignatureVerifier;
import in.gov.uidai.auth.device.model.AuthDataFromDeviceToAUA;
import in.gov.uidai.auth.device.model.DeviceCollectedAuthData;
import in.gov.uidai.auth.device.model.OtpDataFromDeviceToAUA;
import in.gov.uidai.authentication.otp._1.OtpRes;
import in.gov.uidai.authentication.otp._1.OtpResult;
import in.gov.uidai.authentication.uid_auth_request._1.Tkn;
import in.gov.uidai.authentication.uid_auth_request_data._1.BioMetricType;
import in.gov.uidai.authentication.uid_auth_request_data._1.BiometricPosition;
import in.gov.uidai.kyc.common.types._1.YesNoType;
import in.gov.uidai.kyc.uid_kyc_response._1.KycRes;

public class KycTestCDSLProdV2Sample {

	private String clientId;
	private String auaCode;
	private String subAuaCode;
	private String kuaLicenseKey;
	
	private String uidaiPidEncryptionCertificate;
	private String asaGatewaySigner;
	private String auaSigningCertificate;
	private String auaSigningCertificatePassword;
	private String asaUrl;
	private String udc;
	
	private String residentAadhaarNumber;

	public static void main(String[] args) throws Exception{
		// TODO Auto-generated method stub
		
		KycTestCDSLProdV2Sample kyc = new KycTestCDSLProdV2Sample();
		
		kyc.initConfig();
		
		kyc.testKyc();
		
		//kyc.testOtpGeneration();
		//kyc.testKycOtp("637775");
	}
	
	private void initConfig()
	{

		clientId="***CLIENT-ID****";
		auaCode="***REPLACE WITH AUA CODE ******";
		subAuaCode="***** REPLACE SUB AUA CODE ****";
		kuaLicenseKey="********* REPLACE WITH KUA LICENSE KEY ****************";

		uidaiPidEncryptionCertificate="./uidai_auth_prod.cer";
		asaGatewaySigner = "./CDSL_ASA_GW_PRD.cer";

		auaSigningCertificate="./YOUR PFX.pfx";
		auaSigningCertificatePassword="**** REPLACE WITH PFX PASSWORD *****";
		
		asaUrl="https://ksa.cdslindia.com/ECSAsaKsaClientGatewayV2/AsaKsaGatewayClientInterfaceV2";
		
		residentAadhaarNumber="**** REPLACE WITH RESIDENT AADHAAR NUMBER **********";
		udc = "**** REPLACE WITH UNIQUE DEVICE CODE **********"; // eg., "MUDC0000000001"
	}
	public void testKyc() throws Exception
	{
		KycProcessor pro  = new KycProcessor();
		
		// To demonstrate the API, the following lines of code reads the Fingerprint template from file. In producion scenario, AUA/KUA should always capture 
		// live biometrics using STQC certified biometric device
		
		File fileBio = new File("/AuthClientISO/finger_prabu_iso_working_left_index.fmr");
		int bioLength = (int) fileBio.length();
		byte[] biometrics = new byte[bioLength];
		
		
		FileInputStream dis = new FileInputStream(fileBio);
		dis.read(biometrics);
		dis.close();
				
		List<DeviceCollectedAuthData.BiometricData> bioCaptures = new ArrayList<DeviceCollectedAuthData.BiometricData>();
		bioCaptures.add(new DeviceCollectedAuthData.BiometricData(BiometricPosition.UNKNOWN,BioMetricType.FMR, biometrics));
		
		/* Prepare PID Block - The following code is recommended to be executed in the system capturing Biometric data */
		// Auth API  2.0 
		//AuthDataFromDeviceToAUA deviceData = pro.prepareAuaDataV2(residentAadhaarNumber,bioCaptures,false,uidaiPidEncryptionCertificate,false,"public","NC","NA","NA",null,null,null, null,null,null,udc);

		// Auth API 1.6
		String pincode = "560092"; // Applicable for Auth API 1.6
		AuthDataFromDeviceToAUA deviceData = pro.prepareAuaData(residentAadhaarNumber,bioCaptures,false,uidaiPidEncryptionCertificate,false,"public","NC","NA","P",pincode,"127.0.0.1",udc);
		
		/* Prepare ASA Data */
		/* Create Instance of DigitalSigner for signing AUA KYC Packet. If the DigitalSigning of KYC Packet is deligated to ASA then the DigitalSigner shall  be null */
		DigitalSigner auasigner = null; 
		
		/* Create Instance of DigitalSigner for signing the Overall ASA packet using the AUA Private Key (Generated using ECS Key Generation Utility) */
		DigitalSigner gatewaySigner = new DigitalSigner(auaSigningCertificate, auaSigningCertificatePassword.toCharArray());

		boolean pfrFlag = true; // Print Format Request - PDF
		String transactionId = clientId + new Date().getTime(); // Should be Unique
		String asaXML = pro.prepareAsaDataV2(clientId,transactionId,auaCode,subAuaCode,kuaLicenseKey,true,
				true,true,true,true,"FMR",false,false,false,false,false,pfrFlag,deviceData,auasigner,gatewaySigner);
		
		System.out.println("REQUEST TO ASA: " + asaXML);

		/* Send the Kyc Request XML to ECS ASA/KSA */
		String asaResponseXML = pro.sendToAsa(asaUrl, asaXML); 
		
		System.out.println("RESPONSE FROM ASA: " +  asaResponseXML);
	
		if(asaResponseXML.startsWith("<Error>"))
		{
			System.out.println("Error occured - " + pro.getErrorMessage(asaResponseXML));
			return;
		}
		
		/* Prepare SignatureVerifier object for validating the DigitalSignature of XML received from ASA using ASA Gateway Public Key */
		SignatureVerifier gatewayVerifier = new SignatureVerifier(asaGatewaySigner);

		/* Validate XML and Deserialize Ksa response XML */
		KsaKycResponse ksaRes = pro.processKsaResponse(asaResponseXML,gatewayVerifier);

		if(ksaRes.isError() == false)
		{
			try
			{
				KycRes  kycres = pro.getKycRes(ksaRes, null, false);
				if(kycres.getRet() == YesNoType.Y)
				{
					System.out.println("KYC Passed");
					
					// POI
					System.out.println("Name: " + kycres.getUidData().getPoi().getName());
					System.out.println("Date of Birth: " + kycres.getUidData().getPoi().getDob());
					System.out.println("Gender: " + kycres.getUidData().getPoi().getGender());
					System.out.println("Phone: " + kycres.getUidData().getPoi().getPhone());
					System.out.println("Email: " + kycres.getUidData().getPoi().getEmail());

					//POA
					System.out.println("Care Of: " + kycres.getUidData().getPoa().getCo());
					System.out.println("House Number: " + kycres.getUidData().getPoa().getHouse());
					System.out.println("Street: " + kycres.getUidData().getPoa().getStreet());
					System.out.println("Landmark: " + kycres.getUidData().getPoa().getLm());
					System.out.println("Locality: " + kycres.getUidData().getPoa().getLoc());
					System.out.println("Village/Taluka/City: " + kycres.getUidData().getPoa().getVtc());
					System.out.println("Sub District: " + kycres.getUidData().getPoa().getSubdist());
					System.out.println("District: " + kycres.getUidData().getPoa().getDist());
					System.out.println("State: " + kycres.getUidData().getPoa().getState());
					System.out.println("Pincode: " + kycres.getUidData().getPoa().getPc());
					System.out.println("Post Office: " + kycres.getUidData().getPoa().getPo());

					// Photo
					System.out.println("Photo (JPG):" +kycres.getUidData().getPht());
					
					// Check for PDF Data
					if(kycres.getUidData().getPrn() != null)
					{
						FileOutputStream fos = new FileOutputStream(new File("./" + kycres.getUidData().getUid() + ".pdf"));
						fos.write(in.ecs.utils.Base64.decode(kycres.getUidData().getPrn().getValue()));
						fos.close();
						
						System.out.println("PDF Saved");
					}
				}
				else
				{
					System.out.println("KYC Failed - Error Code : " + kycres.getErr());
				}
			}catch(Exception ex)
			{
				ex.printStackTrace();
			}
		}
		else
		{
			System.out.println("Error Code: " + ksaRes.getStatusCode());
			System.out.println("Error Description: " + ksaRes.getStatusDescription());
		}
	}
	
	public void testOtpGeneration() throws Exception
	{
		OtpProcessor pro = new OtpProcessor();
		
		// 487737750373
		/*** Prepare Otp Data Object ***/
		OtpDataFromDeviceToAUA authData = pro.prepareAuaData(residentAadhaarNumber,"public","00");

		/* Prepare ASA Data */
		/* Create Instance of DigitalSigner for signing AUA Otp Packet. If the DigitalSigning of OTP Packet is deligated to ASA then the DigitalSigner shall  be null */
		DigitalSigner auasigner = null; 
		
		/* Create Instance of DigitalSigner for signing the Overall ASA packet using the AUA Private Key (Generated using ECS Key Generation Utility) */
		DigitalSigner gatewaySigner = new DigitalSigner(auaSigningCertificate, auaSigningCertificatePassword.toCharArray());

		Tkn tkn = null;
		String transactionId = clientId +"-" + new Date().getTime(); // Should be Unique
		String asaXML = pro.prepareAsaData(clientId,transactionId,"1.6", auaCode,subAuaCode,kuaLicenseKey,authData,auasigner,gatewaySigner);
		
		System.out.println("REQUEST TO ASA: " + asaXML);

		/* Send the Otp Request XML to ECS ASA/KSA */
		String asaResponseXML = pro.sendToAsa(asaUrl, asaXML); 
		
		System.out.println("RESPONSE FROM ASA: " + asaResponseXML);
		
		if(asaResponseXML.startsWith("<Error>"))
		{
			System.out.println("Error occured - " + pro.getErrorMessage(asaResponseXML));
			return;
		}
		
		/* Prepare SignatureVerifier object for validating the DigitalSignature of XML received from ASA using ASA Gateway Public Key */
		SignatureVerifier gatewayVerifier = new SignatureVerifier(asaGatewaySigner);

		/* Validate XML and Deserialize Asa response XML */
		AsaOtpResponse asaRes = pro.processAsaResponse(asaResponseXML,gatewayVerifier);

		if(asaRes.isError() == false)
		{
			OtpRes  otpres = pro.getOtpRes(asaRes);
			if(otpres.getRet() == OtpResult.y)
			{
				if(otpres.getInfo() == null) // 1.5 API
					System.out.println("Otp generation Successful!");
				else // 1.6 API
				{
					// Extract Masked Mobile Number and EMail
					String[] listInfo = otpres.getInfo().split(",");
					String maskedMobileNumber = listInfo[7];
					String maskedEmail = "";
					if(listInfo[8].endsWith("}"))
						maskedEmail = listInfo[8].substring(0, listInfo[8].length()-1);
						else
							maskedEmail = listInfo[8];

					if(maskedEmail.compareTo("NA") == 0)
						maskedEmail = "";
					
					if(maskedEmail.trim().length() > 0)
						System.out.println("OTP Sent to Mobile Number ending with " + maskedMobileNumber + " and Email Id ending with " + maskedEmail);
					else
						System.out.println("OTP Sent to Mobile Number ending with " + maskedEmail);
					}
				}
			
			else
			{
				System.out.println("Otp generation Failed! - Error Code: " + otpres.getErr());
			}
		}
		else
		{
			System.out.println("Error Code: " + asaRes.getStatusCode());
			System.out.println("Error Description: " + asaRes.getStatusDescription());
		}
	}

	public void testKycOtp(String otp) throws Exception
	{
		KycProcessor pro  = new KycProcessor();
		
		/* Prepare PID Block - The following code is recommended to be executed in the system capturing Biometric data */
		// Auth API  2.0 
		//AuthDataFromDeviceToAUA deviceData = pro.prepareAuaDataV2(residentAadhaarNumber,bioCaptures,false,uidaiPidEncryptionCertificate,false,"public","NC","NA","NA",null,null,null, null,null,null,udc);

		// Auth API 1.6
		String pincode = "560092"; // Applicable for Auth API 1.6
		AuthDataFromDeviceToAUA deviceData = pro.prepareAuaData(residentAadhaarNumber,null,otp,false,uidaiPidEncryptionCertificate,false,"public","NC","NA","P",pincode,"127.0.0.1",udc);

		/* Prepare ASA Data */
		/* Create Instance of DigitalSigner for signing AUA KYC Packet. If the DigitalSigning of KYC Packet is deligated to ASA then the DigitalSigner shall  be null */
		DigitalSigner auasigner = null; 
		
		/* Create Instance of DigitalSigner for signing the Overall ASA packet using the AUA Private Key (Generated using ECS Key Generation Utility) */
		DigitalSigner gatewaySigner = new DigitalSigner(auaSigningCertificate, auaSigningCertificatePassword.toCharArray());

		boolean pfrFlag = true; // Print Format Request - PDF
		String transactionId = clientId + new Date().getTime(); // Should be Unique
		String asaXML = pro.prepareAsaDataV2(clientId,transactionId,auaCode,subAuaCode,kuaLicenseKey,true,
				true,true,true,false,"OTP",true,false,false,false,false,pfrFlag,deviceData,auasigner,gatewaySigner);
				
		System.out.println("REQUEST TO ASA: " + asaXML);

		/* Send the Kyc Request XML to ECS ASA/KSA */
		String asaResponseXML = pro.sendToAsa(asaUrl, asaXML); 
	
		System.out.println("RESPONSE FROM ASA: " + asaResponseXML);

		if(asaResponseXML.startsWith("<Error>"))
		{
			System.out.println("Error occured - " + pro.getErrorMessage(asaResponseXML));
			return;
		}
		
		/* Prepare SignatureVerifier object for validating the DigitalSignature of XML received from ASA using ASA Gateway Public Key */
		SignatureVerifier gatewayVerifier = new SignatureVerifier(asaGatewaySigner);

		/* Validate XML and Deserialize Ksa response XML */
		KsaKycResponse ksaRes = pro.processKsaResponse(asaResponseXML,gatewayVerifier);

		if(ksaRes.isError() == false)
		{
			try
			{
				
				KycRes  kycres = pro.getKycRes(ksaRes, null, false);
				if(kycres.getRet() == YesNoType.Y)
				{
					System.out.println("KYC Passed");
					
					// POI
					System.out.println("Name: " + kycres.getUidData().getPoi().getName());
					System.out.println("Date of Birth: " + kycres.getUidData().getPoi().getDob());
					System.out.println("Gender: " + kycres.getUidData().getPoi().getGender());
					System.out.println("Phone: " + kycres.getUidData().getPoi().getPhone());
					System.out.println("Email: " + kycres.getUidData().getPoi().getEmail());

					//POA
					System.out.println("Care Of: " + kycres.getUidData().getPoa().getCo());
					System.out.println("House Number: " + kycres.getUidData().getPoa().getHouse());
					System.out.println("Street: " + kycres.getUidData().getPoa().getStreet());
					System.out.println("Landmark: " + kycres.getUidData().getPoa().getLm());
					System.out.println("Locality: " + kycres.getUidData().getPoa().getLoc());
					System.out.println("Village/Taluka/City: " + kycres.getUidData().getPoa().getVtc());
					System.out.println("Sub District: " + kycres.getUidData().getPoa().getSubdist());
					System.out.println("District: " + kycres.getUidData().getPoa().getDist());
					System.out.println("State: " + kycres.getUidData().getPoa().getState());
					System.out.println("Pincode: " + kycres.getUidData().getPoa().getPc());
					System.out.println("Post Office: " + kycres.getUidData().getPoa().getPo());

					// Photo
					System.out.println("Photo (JPG):" +kycres.getUidData().getPht());

					// Check for PDF Data
					if(kycres.getUidData().getPrn() != null)
					{
						FileOutputStream fos = new FileOutputStream(new File("./" + kycres.getUidData().getUid() + ".pdf"));
						fos.write(in.ecs.utils.Base64.decode(kycres.getUidData().getPrn().getValue()));
						fos.close();
						
						System.out.println("PDF Saved");
					}
				}
				else
				{
					System.out.println("KYC Failed - Error Code : " + kycres.getErr());
				}
			}catch(Exception ex)
			{
				ex.printStackTrace();
			}
		}
		else
		{
			System.out.println("Error Code: " + ksaRes.getStatusCode());
			System.out.println("Error Description: " + ksaRes.getStatusDescription());
		}
	}
}
