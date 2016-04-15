/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * $Id: GPCard.java 3 2013-07-23 16:00:13Z grandamp@gmail.com $
 *
 * The KeySupport.org PIV API is free software: you can redistribute it
 * and/or modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This code is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with the KeySupport.org PIV API.  If not,
 * see <http://www.gnu.org/licenses/>.
 *
 * @author Todd E. Johnson (tejohnson@yahoo.com)
 * @version $Revision: 3 $
 * Last changed: $LastChangedDate: 2013-07-23 10:00:13 -0600 (Tue, 23 Jul 2013) $
 *****************************************************************************/
package org.keysupport.globalplatform;

/**
 * GP is a reference to GlobalPlatform, derived from OpenPlatform.
 * 
 * See:  http://www.globalplatform.org/
 * 
 * As stated in the license(s) above and below, this code is intended to be an open
 * source "product" derived using the GlobalPlatform specification(s). This code
 * implements this the GlobalPlatform Specification(s) and is not deemed to be 
 * derivative works of the Specification(s).
 * 
 * Licensing Consideration(s):
 * 
 * http://http://globalplatform.org/specificationform.asp?fid=1
 * (retrieved 20130628, 17:45 EST)
 * 
 * From the URL Above:
 * 
 * "Upon completion of the contact information and indication of your 
 * acceptance of the License Agreement, all interested parties are 
 * welcome to download the GlobalPlatform Specifications. Please note 
 * that this license covers both evaluation and product development.
 * As a result, you do not need to complete a new License Agreement  
 * if you decide to go on to develop and sell a product using these 
 * specifications. All rights granted under the License Agreement are 
 * provided at no charge."
 * 
 * (PII for Author entered @ retrieved 20130628, 17:48 EST where entity
 * being represented was "Self")
 * 
 * License Page:
 * 
 * http://globalplatform.org/specificationlicense.asp
 * 
 * Contents: 
 * 
 * "LICENSE AGREEMENT
 * 
 * This License Agreement (Agreement) is a legal agreement between you and 
 * GlobalPlatform, Inc. (Licensor), which is the owner of the specification 
 * (Specification) you will be downloading when you complete this Agreement. 
 * As used in this Agreement, "you" means the company, entity or individual 
 * that is acquiring a license under this Agreement.
 * 
 * By clicking on the "ACCEPT" button below, you are agreeing that you will 
 * be bound by and are becoming a party to this Agreement. If you are an 
 * entity, and an individual is entering into this Agreement on your behalf, 
 * then you will be bound by this Agreement when that individual clicks on 
 * the "ACCEPT" button. When they do so, it will also constitute a 
 * representation by the individual that s/he is authorized to bind you as 
 * a party to this Agreement. If you do not agree to all of the terms of 
 * this Agreement, click the "DO NOT ACCEPT" button at the end of this 
 * Agreement.
 * 
 * 1. License Grant.
 * Licensor hereby grants you the right, without charge, on a perpetual, 
 * non- exclusive and worldwide basis, the right to utilize the Specification 
 * for the purpose of developing, making, having made, using, marketing, 
 * importing, offering to sell or license, and selling or licensing, and 
 * to otherwise distribute, products complying with the Specification, 
 * in all cases subject to the conditions set forth in this Agreement and 
 * any relevant patent and other intellectual property rights of third 
 * parties (which may include members of Licensor). This license grant 
 * does not include the right to sublicense, modify or create derivative 
 * works based upon the Specification. For the avoidance of doubt, products 
 * implementing this Specification are not deemed to be derivative works 
 * of the Specification.
 * 
 * 2. NO WARRANTIES.
 * THE SPECIFICATION IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF 
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, ACCURACY, 
 * COMPLETENESS AND NONINFRINGEMENT OF THIRD PARTY RIGHTS. IN NO EVENT 
 * SHALL LICENSOR, ITS MEMBERS OR ITS CONTRIBUTORS BE LIABLE FOR ANY 
 * CLAIM, OR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES, 
 * OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, 
 * WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, 
 * ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THE 
 * SPECIFICATION.
 * 
 * 3. THIRD PARTY RIGHTS.
 * Without limiting the generality of Section 2 above, LICENSOR ASSUMES 
 * NO RESPONSIBILITY TO COMPILE, CONFIRM, UPDATE OR MAKE PUBLIC ANY THIRD 
 * PARTY ASSERTIONS OF PATENT OR OTHER INTELLECTUAL PROPERTY RIGHTS THAT 
 * MIGHT NOW OR IN THE FUTURE BE INFRINGED BY AN IMPLEMENTATION OF THE 
 * SPECIFICATION IN ITS CURRENT, OR IN ANY FUTURE FORM. IF ANY SUCH 
 * RIGHTS ARE DESCRIBED ON THE SPECIFICATION, LICENSOR TAKES NO POSITION 
 * AS TO THE VALIDITY OR INVALIDITY OF SUCH ASSERTIONS, OR THAT ALL SUCH 
 * ASSERTIONS THAT HAVE OR MAY BE MADE ARE SO LISTED.
 * 
 * 4. TERMINATION OF LICENSE.
 * In the event of a breach of this Agreement by you or any of your employees 
 * or members, Licensor shall give you written notice and an opportunity to 
 * cure. If the breach is not cured within thirty (30) days after written 
 * notice, or if the breach is of a nature that cannot be cured, then 
 * Licensor may immediately or thereafter terminate the licenses granted 
 * in this Agreement.
 * 
 * 5. MISCELLANEOUS.
 * All notices required under this Agreement shall be in writing, and shall 
 * be deemed effective five days from deposit in the mails. Notices and 
 * correspondence to either party shall be sent to its address as it appears 
 * below. This Agreement shall be construed and interpreted under the internal 
 * laws of the United States and the State of California, without giving 
 * effect to its principles of conflict of law.
 * 
 * GlobalPlatform, Inc.
 * 544 Hillside Road
 * Redwood City, CA 94062
 * USA GlobalPlatform, Inc.
 * 
 * 6. EXPORT REGULATIONS.
 * The Specification, or portions thereof, including technical data, may be 
 * subject to U.S. export control laws, including the U.S. Export Administration 
 * Act and its associated regulations, and may be subject to export or import 
 * regulations in other countries. Licensee agrees to comply strictly with all 
 * such regulations and acknowledges that it has the responsibility to obtain 
 * all export, re-export, import or other licenses in connection with its use 
 * of the Specification or any product complying with the Specification.
 * 
 * 7. RESTRICTED RIGHTS.
 * Use, duplication or disclosure by the United States government is subject 
 * to the restrictions as set forth in the Rights in Technical Data and Computer 
 * Software Clauses in DFARS 252.227-7013© (1) (ii) and FAR 52.227- 19(a) 
 * through (d) as applicable.
 * 
 * Click below to indicate your acceptance of this Agreement.
 * 
 * Click below if you do not wish to have your identity or your company's 
 * identity included in GlobalPlatform marketing materials.
 * 
 *  "X" I do not wish to have my identity or my company's identity included in 
 *  GlobalPlatform marketing materials or otherwise revealed to third parties."
 *  
 *  (Option to withhold identity from marketing materials and third parties 
 *  selected, and "Accept" button selected on 20130628, 18:01 EST by Author.)
 *  
 * The following code was derived by the author using the GlobalPlatform
 * Specifications as a guide to communicate with Card technologies 
 * implementing the specification.  The target version is the following
 * API specification and lower:
 * 
 *   -GlobalPlatform Card Specification v2.1.1
 *   
 * This code may or may not implement all of the features and requirements
 * defined in the specification.
 * 
 * Further, any entity contributing to code in the following package
 * (or sub-packages) of this API should be aware of GlobalPlatform's I.P.
 * disclaimers, and should not derive or contribute any code that would
 * infringe any of the I.P. that has been claimed:
 * 
 * http://globalplatform.org/specificationsipdisclaimers.asp
 * 
 * KSJava API Package: org.keysupport.globalplatform
 * 
 * All code derived in this package and sub-packages SHOULD remain
 * product agnostic, and SHOULD NOT include references to any vendors
 * nor vendor implementations.  It is entirely up to the caller of the
 * code in these packages to establish license agreements or 
 * non-disclosure agreements with vendors in order to work with a specific
 * product, and should be independent of this code base.
 * 
 * Finally, prior open source works based on GlobalPlatform Specifications
 * have been listed below, however, it may not represent a comprehensive
 * list of open source work:
 * 
 * -http://sourceforge.net/projects/globalplatform
 * -http://sourceforge.net/projects/gpj
 * 
 **/
public class GPCard {
	
	public final static byte GP_COMMAND = (byte) 0x00;
	public final static byte GP_COMMAND_CC = (byte) 0x10;
	public final static byte GP_SELECT = (byte) 0xa4;
	
	/*
	 * Card Life Cycle States
	 */
	//OP_READY
	//INITIALIZED
	//SECURED
	//CARD_LOCKED
	//TERMINATED
	
	/*
	 * Application Life Cycle States
	 */
	//INSTALLED
	//SELECTABLE
	//LOCKED
	
	/*
	 * Security Domain Life Cycle States
	 */
	//INSTALLED
	//SELECTABLE
	//PERSONALIZED
	//LOCKED
	
	/*
	 * CVM States
	 */
	//ACTIVE
	//INVALID_SUBMISSION
	//VALIDATED
	//BLOCKED
	
	/*
	 * Tags
	 */
	byte[] IIN = new byte[] { (byte)0x42 }; //Issuer Identification Number
	byte[] CIN = new byte[] { (byte)0x45 }; //Card Image Number
	byte[] CRD = new byte[] { (byte)0x73 }; //Card Recognition Data
	byte[] CARD_DATA = new byte[] { (byte)0x66 }; //Card Data Template
	
	/*
	 * Secure Channel Protocol Identifier(s)
	 */
	//SCP_01
	//SCP_01_05
	//SCP_02
	//SCP_03
	
	/*
	 * Feedback from William C. Petty:  Get data from the ISD to form the CUID:
	 * 
	 * Example:
	 * 
	 *   byte[] GET_DATA_SLCTAID = c2b("00A4040000"); 
     *   response = card.getBasicChannel().transmit(new CommandAPDU(GET_DATA_SLCTAID)); 
     *   byte[] GET_DATA_IIN = c2b("80CA004200"); 
     *   response = card.getBasicChannel().transmit(new CommandAPDU(GET_DATA_IIN)); 
     *   byte[] iinba = response.getData(); 
     *   System.out.println("IIN " + new String(iinba, 2, iinba.length -2)); 
     *   byte[] GET_DATA_CIN = c2b("80CA004500"); 
     *   response = card.getBasicChannel().transmit(new CommandAPDU(GET_DATA_CIN)); 
     *   byte[] cinba = response.getData(); 
     *   System.out.println("CIN " + new String(cinba, 2, cinba.length -2));
     *   
     *   My notes:
     *   
     *   -Establish information on the ISD in order to determine the GP version,
     *    as well as the secure channel version.
     *   -Store the information in the GPCard object to assist with establishing the
     *    secure channel.
     *   -Standard methods should be derived in order to provide utility for injecting
     *    sensitive contents to the card, such as PUK, private keys, etc. 
     *    
     *   Challenges/Remaining questions:
     *   
     *   Some manufacturers use an Application Security Domain versus the Issuer Security
     *   domain to secure the communications during provisioning.  For example, consider
     *   the following PIV hardware:
     *   
     *   Gemalto (general):
     *   
     *   The issuer security domain is provided for lifecycle management, and the PIV
     *   admin key is used to manage the PIV application.
     *   
     *   Sensitive data is secured using the ISD secure channel using the KEK, with MACed
     *   APDUs via a secure channel.
     *   
     *   Oberthur (general):
     *   
     *   The issuer security domain is provided for lifecycle management, and the PIV
     *   admin key is used to manage the PIV application.
     *   
     *   Sensitive data is secured using and application security domain (ASD) secure 
     *   channel using the KEK, with MACed APDUs via a secure channel.
     *   
     *   This requires multiple secure channels to the card via different protocols
     *   which are dependent on Card Management verus Application Management.
     *   
	 */
}
