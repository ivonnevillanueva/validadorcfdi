from utils import XMLValidator
from utils import AmountValidator
from utils import SigningNodeExist
from utils import SealValidator
from utils import DateValidator
from utils import EmissionHoursValidator
from utils import CertificateExpiration 
from utils import SignedSATAuthority 
from utils import FielValidator
from utils import LCOValidator
from utils import SubjectDNValidator
from utils import LCOCSDValidator
from utils import Signing
#from apps.services.utils.services.errors import SoapError 
#from apps.invoicing.util import FileManager
#from apps.services.utils.sat.connector.satws import SATWS
#from apps.services.models import Receipt
#from apps.services.models import Cancellation as SATCancellation
#from apps.services.models import ResellerCancellation
#from apps.services.models import PendingBuffer
#from apps.services.models import PendingBufferCancellation
#from apps.services.models import Invoice
#from apps.services.models import Reseller
#from apps.services.models import ResellerInvoice
#from apps.services.models import ResellerUser
#from apps.services.models import ResellerUserInvoice
#from wis.apps.core.models import Log

#from apps.invoicing.util import pycripto_function_dec
#from apps.invoicing.util import pycripto_function
#from apps.invoicing.util import email_incidents
#from apps.sat.models import lco
from django.utils.translation import ugettext as _

from django.conf import settings 
#from apps.invoicing.models import Account
from django.contrib.auth.models import User

#from apps.services import pending_celery
#from apps.services import pending_celery_cancellation

from datetime import datetime
from datetime import timedelta
import json
from lxml import etree
import hashlib
import pprint
import re
import os
import base64
import cgi
import M2Crypto
from conf.settings import XML_INVOICE_NAMESPACE


class Receives:
  """This class is responsible for controlling the flow of 
     validation for invoices in XML format
  """

  def __init__(self, xml, user=None, original_string=None, signing=True):
    """This is the normal flow of validation of each of the errors 
       mentioned by the SAT and are within diagram validation
    """
    self.xml_string = xml
    self.original_string = original_string
    self.user = user

    self.is_valid = True
    self.certificate = None
    self.certificate_string = ''
    self.uuid = None
    self.cfd_seal = None
    self.sat_seal = None
    self.reseller = None
    self.reseller_passphrase = None
    self.complementNode = None
    self.xml_etree = None
    self.incident_list = []
    self.is_external = False    
    self.addenda = None
    self.addenda_string = ''
    self.cod_status = ''
    if user is not None:
      self.is_external = True
    
    #import pdb; pdb.set_trace()
    self.xml_parser = etree.XMLParser(remove_blank_text=True)
    try:
      xml_encoded = self.xml_string.encode('utf-8')
      try:
        self.xml_etree = etree.XML(xml_encoded, parser=self.xml_parser)
      except Exception, e:
        print str(e)
        self.is_valid = False
        incident = SoapError(self.xml_string,705).fault()
        self.incident_list.append(incident)
    except:
      try:
        self.xml_etree = etree.XML(self.xml_string, parser=self.xml_parser)
      except Exception,e:
        print str(e)
        self.is_valid = False
        incident = SoapError(self.xml_string,705).fault()
        self.incident_list.append(incident)
      
    try:
      self.cfd_seal = self.xml_etree.get('sello')
      self.serial_number = self.xml_etree.get('noCertificado')
      self.taxpayer_id = self.xml_etree.xpath('//tmp:Emisor', namespaces={'tmp':'http://www.sat.gob.mx/cfd/3'})[0].get('rfc')
      self.certificate_string, self.certificate = self.get_certificate(self.xml_etree.get('certificado'))
    except:
      incident = SoapError(self.xml_string,301).fault()
      self.incident_list.append(incident)
      self.is_valid = False
      return

    if self.serial_number != hex(self.certificate.get_serial_number())[3:-1:2]:
      incident = SoapError(self.xml_string,712).fault()
      self.incident_list.append(incident)
      self.is_valid = False
      return

    if not signing:
      return
      
    try:
      tfd = None
      tfd = self.xml_etree.find(XML_INVOICE_NAMESPACE % "Complemento").find("{http://www.sat.gob.mx/TimbreFiscalDigital}TimbreFiscalDigital")
      if tfd is not None:
        incident = SoapError(self.xml_string,707).fault()
        self.incident_list.append(incident)
        self.is_valid = False
        return
    except:
      pass

    if self.is_valid and self.user.get_profile().role == 'S':
      self.reseller_validator()
     
    if self.is_valid or settings.WIS_AVOID_WS_VALIDATORS:
      self.xml_validation()

    #if self.is_valid or settings.WIS_AVOID_WS_VALIDATORS:
    #  self.amount_validation()
      
    if self.is_valid  or settings.WIS_AVOID_WS_VALIDATORS:
      self.signing_node_exist()
      
    if self.is_valid  or settings.WIS_AVOID_WS_VALIDATORS:  
      self.date_invoice_validation()
      
    if self.is_valid  or settings.WIS_AVOID_WS_VALIDATORS:
      self.certificate_expiration_validation()

    if self.is_valid  or settings.WIS_AVOID_WS_VALIDATORS:
      self.signed_by_sat_authority()
    
    if self.is_valid  or settings.WIS_AVOID_WS_VALIDATORS:
      self.fiel_validation()
    
    if self.is_valid  or settings.WIS_AVOID_WS_VALIDATORS:
      self.lco_validator()
      
    if self.is_valid  or settings.WIS_AVOID_WS_VALIDATORS:
      self.subjectdn_validator()
    
    if self.is_valid  or settings.WIS_AVOID_WS_VALIDATORS:
      self.lco_csd_validator()
      
    if self.is_valid  or settings.WIS_AVOID_WS_VALIDATORS:
      self.seal_validator()
    
    if self.is_valid  or settings.WIS_AVOID_WS_VALIDATORS:
      self.emission_hours_validation()

    if self.is_valid  or settings.WIS_AVOID_WS_VALIDATORS:
      self.signing_invoice()
    
  def get_certificate(self, certificate_string=''):
    try:
      split_string_cert = [certificate_string[i:i+64] for i in range(0, len(certificate_string), 64)]
      l = [x + "\n"for x in split_string_cert]
      split_string_cert = l
      split_string_cert = "".join(split_string_cert)
      certificate_string = "-----BEGIN CERTIFICATE-----\n" + \
                                  split_string_cert + \
                                "-----END CERTIFICATE-----"
      x509_cert = M2Crypto.X509.load_cert_string(certificate_string, M2Crypto.X509.FORMAT_PEM)
      return certificate_string, x509_cert
    except:
      pass
    return None

  def reseller_validator(self, reseller=None):
    """
    Validate the correct login user and password of a reseller
    """
    if reseller is not None:
      self.reseller = reseller
    else:
      try:
        self.reseller = Reseller.objects.get(profile=self.user.get_profile())
      except Exception,e:
        pprint.pprint(e)
        incident = SoapError(self.xml_string,706).fault()
        self.incident_list.append(incident)
        self.is_valid = False
        return
    try:
      if self.reseller.status == 'S':
        incident = SoapError(self.xml_string,703).fault()
        self.incident_list.append(incident)
        self.is_valid = False
        return
      self.reseller_passphrase = pycripto_function_dec(self.reseller.passphrase)
      if not settings.LOCALDEV:        
        try:
          if self.reseller.type == 'U':
            reseller_user = ResellerUser.objects.get(reseller=self.reseller, taxpayer_id=self.taxpayer_id)
          if self.reseller.type == 'I':
            reseller_user = ResellerUserInvoice.objects.get(reseller=self.reseller, taxpayer_id=self.taxpayer_id)
          if reseller_user.status == 'S':
            incident = SoapError(self.xml_string,701).fault()
            self.incident_list.append(incident)
            self.is_valid = False
            sys_user = User.objects.get(id=1)
            Log.objects.log_action(
            sys_user, 0, 'S',
            'Action: ResellerUser is Suspended and can not create Invoices.\nReseller:%s\ntaxpayer_id: %s\nUUID: %s' % (self.taxpayer_id, self.reseller.id),
            'E')
            return
        except:
          incident = SoapError(self.xml_string,702).fault()
          self.incident_list.append(incident)
          self.is_valid = False
          sys_user = User.objects.get(id=1)
          Log.objects.log_action(
            sys_user, 0, 'S',
            'Action: ResellerUser Does Not exist\nReseller:%s\ntaxpayer_id: %s\nUUID: %s' % (self.taxpayer_id, self.reseller.id),
            'E')
          return        
    except Exception, e:
      pprint.pprint(e)
      incident = SoapError(self.xml_string,300).fault()
      self.incident_list.append(incident)
      self.is_valid = False
    if settings.WIS_AVOID_WS_VALIDATORS:
      self.is_valid = True 
    return
     
  def xml_validation(self):
    """
    Validate the correct formation of the invoice in xml format "parsing"
    """
    try:
      xml_invoice_parser = XMLValidator(self.xml_etree)
      result = xml_invoice_parser.is_valid()
      if not result["success"]:
        incident = SoapError(self.xml_string,301).fault()
        self.incident_list.append(incident)
        self.is_valid = False
      self.addenda = result['addenda']
      try:
        if self.addenda is not None:
          self.addenda_string = etree.tostring(self.addenda, encoding='UTF-8')
      except:
        pass
      print result
    except Exception, e:
      pprint.pprint(e)
      incident = SoapError(self.xml_string,301).fault()
      self.incident_list.append(incident)
      self.is_valid = False
    if settings.WIS_AVOID_WS_VALIDATORS:
      self.is_valid = True  

  def amount_validation(self):
    """
    Validate the correct amounts in the xml (subtotal, total, taxes)
    """
    try:      
      amount_validator = AmountValidator(self.xml_etree)
      result = amount_validator.is_valid()
      if not result["success"]:
        incident = SoapError(self.xml_string,710).fault()
        incident.MensajeIncidencia = result['message']
        self.incident_list.append(incident)
        self.is_valid = False
      print result
    except Exception, e:
      pprint.pprint(e)
      incident = SoapError(self.xml_string,710).fault()
      self.incident_list.append(incident)
      self.is_valid = False
    if settings.WIS_AVOID_WS_VALIDATORS:
      self.is_valid = True 
  
  def signing_node_exist(self):
    """Validate if the signing node exist
    """
    try:
      signing_node_exist = SigningNodeExist(self.xml_etree)
      result = signing_node_exist.is_valid()
      print result
      if not result["success"]:
        incident = SoapError(self.xml_string,307).fault()
        self.incident_list.append(incident)
        self.is_valid = False
    except Exception, e:
      pprint.pprint(e)
      incident = SoapError(self.xml_string,307).fault()
      self.incident_list.append(incident)
      self.is_valid = False
    if settings.WIS_AVOID_WS_VALIDATORS:
      self.is_valid = True 
           
  def date_invoice_validation(self):
    """
    Verifies that the date of issuance is after January 1st 2012
    """
    try:
      date_invoice_validator = DateValidator(self.xml_etree)
      result = date_invoice_validator.is_valid()
      print result
      if not result["success"]:
        incident = SoapError(self.xml_string,403).fault()
        self.incident_list.append(incident)
        self.is_valid = False
    except Exception, e:
      pprint.pprint(e)
      incident = SoapError(self.xml_string,403).fault()
      self.incident_list.append(incident)
      self.is_valid = False
    if settings.WIS_AVOID_WS_VALIDATORS:
      self.is_valid = True 
    
  def emission_hours_validation(self):
    """
    Verify that this invoice was created within the 72 hours that SAT requires
    """
    try:
      emission_hours_validator = EmissionHoursValidator(self.xml_etree)
      result = emission_hours_validator.is_valid()
      print result
      if not result["success"]:
        incident = SoapError(self.xml_string,401).fault()
        self.incident_list.append(incident)
        self.is_valid = False
    except Exception,e:
      
      pprint.pprint(e)
      incident = SoapError(self.xml_string,401).fault()
      self.incident_list.append(incident)
      self.is_valid = False
    if settings.WIS_AVOID_WS_VALIDATORS:
      self.is_valid = True 
      
  def certificate_expiration_validation(self):
    """Emission date is within the date of the certificate issuer
    """
    try:
      certificate_expiration = CertificateExpiration(self.xml_etree, self.certificate)
      result = certificate_expiration.is_valid()
      print result
      if not result["success"]:
        incident = SoapError(self.xml_string,305).fault()
        self.incident_list.append(incident)
        self.is_valid = False
    except Exception, e:
      pprint.pprint(e)
      incident = SoapError(self.xml_string,305).fault()
      self.incident_list.append(incident)
      self.is_valid = False
    if settings.WIS_AVOID_WS_VALIDATORS:
      self.is_valid = True 

  def signed_by_sat_authority(self):
    """Validate that the issuer CSD has been signed by a Certificate Authority of the SAT
    """ 
    try:
      signed_sat = SignedSATAuthority(self.xml_etree, self.certificate)
      result = signed_sat.is_valid()  
      print result
      if not result["success"]:
        incident = SoapError(self.xml_string,308).fault()
        self.incident_list.append(incident)
        self.is_valid = False
    except Exception,e:
      pprint.pprint(e)
      incident = SoapError(self.xml_string,308).fault()
      self.incident_list.append(incident)
      self.is_valid = False
    if settings.WIS_AVOID_WS_VALIDATORS:
      self.is_valid = True 

  def fiel_validation(self):
    """Validate that The issuer certificate is not of type FIEL
    """ 
    try:   
      fiel_validator = FielValidator(self.xml_etree, self.certificate)
      result = fiel_validator.is_valid()
      print result
      if not result["success"]:
        incident = SoapError(self.xml_string,306).fault()
        self.incident_list.append(incident)
        self.is_valid = False
    except Exception, e:
      pprint.pprint(e)
      incident = SoapError(self.xml_string,306).fault()
      self.incident_list.append(incident)
      self.is_valid = False
    if settings.WIS_AVOID_WS_VALIDATORS:
      self.is_valid = True 
    
  def lco_validator(self):
    """Validate that RFC issuer is not in the regime of taxpayers
    """
    try:
      lco_validator = LCOValidator(self.xml_etree, self.certificate)
      result = lco_validator.is_valid()
      print result
      if not result["success"]:
        incident = SoapError(self.xml_string,402).fault()
        self.incident_list.append(incident)
        self.is_valid = False
    except Exception, e:
      pprint.pprint(e)
      incident = SoapError(self.xml_string,402).fault()
      self.incident_list.append(incident)
      self.is_valid = False
    if settings.WIS_AVOID_WS_VALIDATORS:
      self.is_valid = True 
      
  def subjectdn_validator(self):
    """Validate that the issuer CSD not corresponds to RFC sender 
       by proof comes as fiscal invoice
    """ 
    try: 
      subjectdn_validator = SubjectDNValidator(self.xml_etree, self.certificate)
      result = subjectdn_validator.is_valid()
      print result
      if not result["success"]:
        incident = SoapError(self.xml_string,303).fault()
        self.incident_list.append(incident)
        self.is_valid = False
    except Exception, e:
      pprint.pprint(e)
      incident = SoapError(self.xml_string,303).fault()
      self.incident_list.append(incident)
      self.is_valid = False
    if settings.WIS_AVOID_WS_VALIDATORS:
      self.is_valid = True 
      
  def lco_csd_validator(self):
    """Validate that the emitter CSD has not been revoked
    """
    try:
      lco_csd_validator = LCOCSDValidator(self.xml_etree, self.certificate)
      result = lco_csd_validator.is_valid()
      print result
      if not result["success"]:
        incident = SoapError(self.xml_string,304).fault()
        self.incident_list.append(incident)
        self.is_valid = False
    except Exception, e:
      pprint.pprint(e)
      incident = SoapError(self.xml_string,304).fault()
      self.incident_list.append(incident)
      self.is_valid = False
    
    if settings.WIS_AVOID_WS_VALIDATORS:
      self.is_valid = True 
      
  def seal_validator(self):
    """Validate the seal of the CFDI
    """
    try:
      seal_validator = SealValidator(self.xml_etree, self.certificate, self.original_string)
      result = seal_validator.is_valid()
      self.original_string = seal_validator.original_string
      if result["success"]:
        self.original_string = seal_validator.original_string
        self.cfd_seal = seal_validator.sign       
      else:
        incident = SoapError(self.xml_string,302).fault()
        self.incident_list.append(incident)
        self.is_valid = False
    except Exception,e:
      pprint.pprint(e)
      incident = SoapError(self.xml_string,302).fault()
      self.incident_list.append(incident)
      self.is_valid = False
    if settings.WIS_AVOID_WS_VALIDATORS:
      self.is_valid = True 
 
  def signing_invoice(self):
    """This method is responsible for adding the digital stamp 
       attribute to the invoice in xml format
    """
    try:
      signing = Signing(self.xml_etree, self.addenda)
      result = signing.is_valid()
      if result["success"]:
        self.signing_xml_string = signing.xml_string        
        self.signing_pretty_xml_string = signing.pretty_xml_string        
        self.sat_seal = signing.sat_seal
        self.uuid = signing.uuid
        self.stamping_date_str = signing.stamping_date_str
      else:
        incident = SoapError(self.xml_string,709).fault()
        self.incident_list.append(incident)
        self.is_valid = False
    except Exception, e:
      pprint.pprint(e)
    if settings.WIS_AVOID_WS_VALIDATORS:
      self.is_valid = True 
      
  def sat_receives(self):
    """This method is responsible of sending the invoice to the SAT WebServices
    """ 

    invoice_header = self.get_invoice_header()

    if self.is_external:
      if self.reseller is not None:
        reseller_invoice = ResellerInvoice(
          reseller = self.reseller,
          uuid = self.invoice_header['uuid'],
          taxpayer_id = self.invoice_header['taxpayer_id'],
          xml = self.signing_xml_string,
          addenda = self.addenda_string,
          original_string = self.original_string,
          cfdi_seal = self.sat_seal,
          status = 'S'
        )
        reseller_invoice.save()
        self.reseller_invoice = reseller_invoice
      else:
        invoice = Invoice(
          taxpayer_id = self.invoice_header['taxpayer_id'],
          uuid = self.invoice_header['uuid'],
          date = self.invoice_header['date'],
          xml = self.signing_xml_string,
          addenda = self.addenda_string,
          original_string = self.original_string,
          cfdi_seal = self.sat_seal
        )
        invoice.save()
        self.external_invoice = invoice
      
    sat_obj = SATWS()
    if settings.WIS_SAT_CONNECTION:
      type = 'I'
      if self.is_external:
        type = 'E'
      try:
        acuse_recepcion_dict, incidencia_list, acuse_xml = sat_obj.recibe(invoice_header, self.signing_xml_string)
        if not acuse_recepcion_dict.has_key('UUID'):
          acuse_recepcion_dict['UUID'] = invoice_header['uuid']
        if not acuse_recepcion_dict.has_key('faultcode'):
          response = self.store_acuse(acuse_recepcion_dict, incidencia_list, acuse_xml)
        if acuse_recepcion_dict.has_key('CodEstatus'):
          self.cod_status = acuse_recepcion_dict['CodEstatus']
          if re.match(".*recibido.*", acuse_recepcion_dict['CodEstatus']):
            self.is_valid = True
          if re.match(".*rechazado.*", acuse_recepcion_dict['CodEstatus']):
            self.is_valid = False
        else:
          if acuse_recepcion_dict.has_key('faultstring'):
            error = "%s\n%s" % (acuse_recepcion_dict['faultcode'], acuse_recepcion_dict['faultstring'])
          else:
            error = incidencia_list[0]['MensajeIncidencia']
          error = 'SAT Error: %s' % error
          acuse = self.store_pending_buffer(error)      
          if settings.SEND_INCIDENTS_EMAIL and not re.match('.*token validity.*', error):
            try:
              subject = "PendingBuffer SAT: %s %s" % (self.taxpayer_id, invoice_header['uuid'])
              html = "Reseller ID => %s<br/> Reseller Username => %s<br/>Taxpayer ID => %s<br/>UUID => %s<br/>Acuse Recepcion Dict %s<br/>Error => %s" % (
                      self.reseller.id, self.reseller.username, self.taxpayer_id, acuse_recepcion_dict['UUID'], str(acuse_recepcion_dict), error)
              email_incidents(subject, html)
            except:
              pass
          response = {'acuse': acuse, 'incidents':[] }          
      except Exception,e:
          error = 'Exception: %s' % str(e)
          acuse = self.store_pending_buffer(error)
          if settings.SEND_INCIDENTS_EMAIL:
            try:
              subject = "PendingBuffer Exception: %s %s" % (self.taxpayer_id, invoice_header['uuid'])
              html = "Reseller ID => %s<br/> Reseller Username => %s<br/>Taxpayer ID => %s<br/>UUID => %s<br/>Acuse Recepcion Dict %s<br/>Error => %s" % (
                      self.reseller.id, self.reseller.username, self.taxpayer_id, acuse_recepcion_dict['UUID'], str(acuse_recepcion_dict), error)
              email_incidents(subject, html)
            except:
              pass
          response = {'acuse':acuse, 'incidents': []}
    else:    
      # Store PendingBuffer
      error = 'settings.WIS_SAT_CONNECTION = False'
      acuse = self.store_pending_buffer(error)
      response = {'incidents': [], 'acuse': acuse}
    
    return response
      
  def get_invoice_header(self):    
    """This method gets the necessary data from the invoice in xml 
       format to create the connection with the sat
    """
    
    invoice_hash = hashlib.sha1(self.original_string).hexdigest()

    self.invoice_header = {
      'taxpayer_id': self.taxpayer_id,
      'hash': invoice_hash,
      'uuid': self.uuid,
      'date': self.stamping_date_str,
      'certificate_no': settings.WIS_SAT_CERT
    }
    return self.invoice_header

  def store_acuse(self, acuse_recepcion_dict, incidencia_list, acuse_xml):  
    """Storing the generated accuse by sat
    """
    import cgi
    acuse = Receipt(
      uuid = acuse_recepcion_dict['UUID'],
      cod_status = acuse_recepcion_dict['CodEstatus'],
      date = acuse_recepcion_dict['Fecha'],
      certificate_number = acuse_recepcion_dict['NoCertificadoSAT'],
      incidents = json.dumps(incidencia_list),
      xml = acuse_xml,
      taxpayer_id = self.taxpayer_id,
      cfdi_seal = self.cfd_seal
    )
    acuse.save()

    try:
      status = 'S'
      if re.match(".*recibido.*", acuse_recepcion_dict['CodEstatus']):
        if self.reseller_passphrase is not None and self.reseller.type == 'I':
          try:
            reseller_user_invoice = ResellerUserInvoice.objects.get(reseller=self.reseller, taxpayer_id=self.taxpayer_id)
            reseller_user_invoice.counter = reseller_user_invoice.counter + 1          
          except:
            reseller_user_invoice = ResellerUserInvoice(
              reseller=self.reseller, 
              taxpayer_id=self.taxpayer_id
            )
            reseller_user_invoice.counter = 1
          reseller_user_invoice.save()
        elif self.reseller_passphrase is not None and self.reseller.type == 'U':
          try:
            reseller_user = ResellerUser.objects.get(reseller=self.reseller, taxpayer_id=self.taxpayer_id)
            reseller_user.counter = reseller_user.counter + 1          
            reseller_user.save()
          except:
            pass
          
        status = 'F'
        if re.match(".*incidencia.*", acuse_recepcion_dict['CodEstatus']) and settings.SEND_INCIDENTS_EMAIL:
          try:
            subject = "SAT Received with Incidents: %s %s" % (self.taxpayer_id, acuse_recepcion_dict['UUID'])
            html = "<pre>%s</pre>" % cgi.escape(acuse_xml, quote=None)
            email_incidents(subject, html)
          except:
            pass
        if re.match(".*extemp.*", acuse_recepcion_dict['CodEstatus']) and settings.SEND_INCIDENTS_EMAIL:
          try:
            subject = "SAT Received Extemporaneous: %s %s" % (self.taxpayer_id, acuse_recepcion_dict['UUID'])
            html = "<pre>%s</pre>" % cgi.escape(acuse_xml, quote=None)
            email_incidents(subject, html)
          except:
            pass
      else:
        if settings.SEND_INCIDENTS_EMAIL:
          try:
            subject = "SAT Incidents: %s %s" % (self.taxpayer_id, acuse_recepcion_dict['UUID'])
            html = "<pre>%s</pre>" % cgi.escape(acuse_xml, quote=None)
            email_incidents(subject, html)
          except:
            pass

      if self.is_external:
        if self.reseller_passphrase is not None:
          reseller_invoice = self.reseller_invoice      
          reseller_invoice.status = status
          reseller_invoice.save()
        else:
          invoice = self.external_invoice      
          invoice.status = status      
          invoice.save()
    except:
      pass

    incidents = []
    for incidencia in incidencia_list:
      incidents.append(incidencia)

    return {'acuse': acuse_recepcion_dict, 'incidents':incidents }
  
  def store_pending_buffer(self, error='QuickStamp'):  
    """Storing the PendingBuffer so we can send the CFDI to the SAT later
    """
    success = True
    cod_status = 'Comprobante timbrado satisfactoriamente'

    invoice_header = self.get_invoice_header()

    type = 'I'
    if self.is_external:
      type = 'E'

    if self.is_external and error in ('QuickStamp', 'Stamp'): 
      if self.reseller is not None:
        reseller_invoice = ResellerInvoice(
          reseller = self.reseller,
          uuid = self.invoice_header['uuid'],
          taxpayer_id = self.invoice_header['taxpayer_id'],
          xml = self.signing_xml_string,
          addenda = self.addenda_string,
          original_string = self.original_string,
          cfdi_seal = self.sat_seal,
          status = 'S'
        )
        reseller_invoice.save()
        self.reseller_invoice = reseller_invoice
      else:
        invoice = Invoice(
          taxpayer_id = self.invoice_header['taxpayer_id'],
          uuid = self.invoice_header['uuid'],
          date = self.invoice_header['date'],
          xml = self.signing_xml_string,
          addenda = self.addenda_string,
          original_string = self.original_string,
          cfdi_seal = self.sat_seal
        )
        invoice.save()
        self.external_invoice = invoice
    try:      
      next_attempt = datetime.now() + timedelta(minutes=settings.SAT_PENDINGBUFFER_INTERVAL)
      pending_buffer = PendingBuffer(
        uuid = self.uuid,
        next_attempt = next_attempt,
        type = type,
        error = error,
        cfdi_seal = self.cfd_seal
      )
      if self.reseller is not None:
        pending_buffer.reseller = self.reseller
      if re.match(".*rechazado.*", self.cod_status):
        pending_buffer.attempts = 9999
      pending_buffer.save()
      # After sending the pending_buffer process it with pending_celery
      pending_celery.delay(pending_buffer)
    except Exception,e:
      try:
        subject = 'StorePendingBuffer: Internal Error'
        html = "Exception => %s <br/>Error => %s" % (str(e), error)
        email_incidents(subject, html)
      except:
        pass
      cod_status = 'Internal Error on PendingBuffer '
      success = False
      self.is_valid = False

    result = {
      'success' : success,
      'CodEstatus': cod_status,
      'Fecha': self.stamping_date_str,
      'NoCertificadoSAT': settings.WIS_SAT_CERT,
      'UUID': self.uuid
    }

    return result


SAT_FILE_MANAGER = FileManager(valid_types=['octet-stream'])

class Cancellation(object):
  
  def __init__(self, uuids=[], user=None, user_certificate=None, user_key=None, taxpayer_id=None, xml_string=None, store_pending=True):
    self.uuids = uuids
    self.taxpayer_id = taxpayer_id
    self.incident_list = []
    self.user = user
    self.reseller = None
    self.is_valid = False
    self.error = ''
    self.invalid_uuid = None
    self.xml_string = xml_string
    self.out_cancel = False
    self.store_pending = store_pending
    if self.store_pending is None:
      self.store_pending = True

    if self.user.get_profile().role == 'S':
      self.is_reseller = True
      self.reseller = Reseller.objects.get(profile=self.user.get_profile())
      self.user_certificate = user_certificate
      self.user_key = user_key      
      self.user_passphrase = self.reseller.passphrase
      self.user_passphrase_dec = pycripto_function_dec(self.reseller.passphrase)      
    else:
      self.taxpayer_id = self.user.get_profile().account.taxpayer_id
      path = SAT_FILE_MANAGER.location
      self.is_reseller = False
      self.user_certificate = path + "/accounts/%s/satfiles/%s_cer.pem" % ( self.user.get_profile().account.pk, self.user.get_profile().account.pk)
      self.user_key = path + "/accounts/%s/satfiles/%s_key.pem" % ( self.user.get_profile().account.pk, self.user.get_profile().account.pk)
      self.user_passphrase = self.user.get_profile().account.sat_key_password
      self.user_passphrase_dec = pycripto_function_dec( self.user.get_profile().account.sat_key_password )

    if len(self.uuids):
      for uuid in self.uuids:
        try:
          receipts = Receipt.objects.filter(taxpayer_id=self.taxpayer_id, uuid=uuid).order_by('-date')
          if len(receipts):
            receipt = receipts[0]
            if re.match(".*recibido.*", receipt.cod_status):
              self.is_valid = True
          else:
            self.invalid_uuid = uuid
            self.is_valid = False
            self.error = 'UUID: %s No Encontrado' % uuid
            break  
        except:
          pass
    else:
      if self.is_reseller and self.xml_string is not None:
        # Validate that the xml is valid, and it was created with the given cer and key
        
        receives_is_valid = False
        same_certificate = False

        try:
          receives = Receives(self.xml_string, self.user, None, False)
          receives.xml_validation()
          receives.signed_by_sat_authority()
          receives.certificate_expiration_validation()
          receives.lco_validator()
          receives.subjectdn_validator()
          receives.lco_csd_validator()
          receives.seal_validator()          
          if receives.is_valid:
            receives_is_valid = True
          else:
            self.incident_list = receives.incident_list
          if self.user_certificate.rstrip('\n') == receives.certificate_string.rstrip('\n'):
            same_certificate = True
          else:
            self.error = 'El Certificado no concuerda.'
        except:
          pass

        if receives_is_valid and same_certificate:          

          xml_etree = etree.fromstring(self.xml_string)
          tfd = xml_etree.xpath('//tmp:TimbreFiscalDigital', namespaces={'tmp':'http://www.sat.gob.mx/TimbreFiscalDigital'})[0]
          uuid = tfd.get('UUID')
          
          emisor = xml_etree.xpath('//tmp:Emisor', namespaces={'tmp':'http://www.sat.gob.mx/cfd/3'})[0]
          invoice_taxpayer_id = emisor.get('rfc')

          if self.taxpayer_id == invoice_taxpayer_id:
            self.uuids = [uuid]
            self.is_valid = True
            self.out_cancel = True
          else:
            self.error = 'El RFC del Emisor no concuerda.'


  def sat_cancellation(self):
    if not self.is_valid:
      return {'cancela_cfd_result': {'RfcEmisor':self.taxpayer_id, 'Fecha':unicode(datetime.now())}, 'folios': [{'UUID':self.invalid_uuid, 'EstatusUUID':'404'}], 'faultcode': self.error, 'faultstring': self.error}
    sat_obj = SATWS()
    type = 'I'
    if self.is_reseller:
      type = 'E'
      if self.out_cancel:
        type = 'O'
    self.type = type
    faultcode = ''
    faultstring = ''
    cancellation_xml = ''
    if settings.WIS_SAT_CONNECTION:
      try:                
        cancela_cfd_dict, folio_list, cancellation_xml, faultcode, faultstring = sat_obj.cancela(self.uuids, self.taxpayer_id, self.user_certificate, self.user_key, self.user_passphrase_dec, self.is_reseller)
        if faultcode != "" and faultstring != "":
          if cancellation_xml in (704, 711):
            return {'cancela_cfd_result': {'RfcEmisor':self.taxpayer_id, 'Fecha': unicode(datetime.now())}, 'folios': [{'UUID':self.uuids[0], 'EstatusUUID':str(cancellation_xml)}], 'faultcode': faultcode, 'faultstring': faultstring} 
          else:
            raise ValueError, "There was an error with SAT Services"
        response = self.store_cancellation(cancela_cfd_dict, folio_list, cancellation_xml, faultcode, faultstring)
      except Exception,e:
        if self.store_pending:
          error = 'SAT Cancellation: Exception => %s' % str(e)
          if faultcode != '' and faultstring != '':
            error = "SAT Cancellation: faultcode => %s ; faultstring => %s" % (faultcode, faultstring)
          pending = self.store_pending_buffer_cancellation(error)

        f_list = []
        for uuid in self.uuids:        
          f_list.append({'UUID':uuid, 'EstatusUUID':'708'})
        response = {
          'cancela_cfd_result': {
            'RfcEmisor': self.taxpayer_id,
            'Fecha':str(datetime.now())
          }, 
          'folios':f_list, 
          'faultcode': '', 
          'faultstring': ''
        }
    else:
      if self.store_pending:
          error = 'SAT Cancellation: Exception => %s' % str(e)
          if faultcode != '' and faultstring != '':
            error = "SAT Cancellation: faultcode => %s ; faultstring => %s" % (faultcode, faultstring)
          pending = self.store_pending_buffer_cancellation(error)
      response = {'cancela_cfd_result': {'RfcEmisor':self.taxpayer_id, 'Fecha':'2012-09-18T15:55:15.3415556'}, 'folios': [{'UUID':'D24B7071-8A1E-4B09-8AD3-BA51B9DCA151', 'EstatusUUID':'201'}], 'faultcode': 'faultcode', 'faultstring': 'faultstring'}
    response['acuse'] = cancellation_xml
    return response

  def store_cancellation(self, cancela_cfd_dict, folio_list, cancellation_xml, faultcode, faultstring):    

    if cancela_cfd_dict.has_key('RfcEmisor') and cancela_cfd_dict.has_key('Fecha'):
      cod_estatus = None
      if cancela_cfd_dict.has_key('CodEstatus'):
        cod_estatus = cancela_cfd_dict['CodEstatus']

      for folio in folio_list:
        cancellation = SATCancellation(
          taxpayer_id = cancela_cfd_dict['RfcEmisor'],
          cod_status = cod_estatus,
          date = cancela_cfd_dict['Fecha'],
          uuid = folio['UUID'],
          uuid_status = folio['EstatusUUID'],
          faultcode = faultcode,
          faultstring = faultstring,
          xml = cancellation_xml
        )
        cancellation.save()
        if self.is_reseller:
          reseller_cancellation = ResellerCancellation(
            reseller = self.reseller,
            uuid = folio['UUID'],
            taxpayer_id = cancela_cfd_dict['RfcEmisor'],
            xml = cancellation_xml,
            type = self.type,
            uuid_status = folio['EstatusUUID']
          )
          reseller_cancellation.save()

          # Verify if the uuid_status is ('201', '202') ???
          if self.reseller.type == 'I':
            try:
              reseller_user_invoice = ResellerUserInvoice.objects.get(reseller=self.reseller, taxpayer_id=self.taxpayer_id)
              reseller_user_invoice.cancel_counter = reseller_user_invoice.cancel_counter + 1          
              reseller_user_invoice.save()
            except:
              pass
          elif self.reseller.type == 'U':
            try:
              reseller_user = ResellerUser.objects.get(reseller=self.reseller, taxpayer_id=self.taxpayer_id)
              reseller_user.cance_counter = reseller_user.cancel_counter + 1          
              reseller_user.save()
            except:
              pass

    elif len(faultcode) and len(faultstring):      
      Log.objects.log_action(
           self.user, 2, 'A',
          'Action: Invoice Cancellation\ntaxpayer_id: %s\nUUID: %s\nfaultcode: %s\nfaultstring: %s' % (self.taxpayer_id, json.dumps(self.uuids), faultcode, faultstring),
          'X')

    folios = []
    for folio in folio_list:
      folios.append(folio)

    return {'cancela_cfd_result': cancela_cfd_dict, 'folios': folios, 'faultcode': faultcode, 'faultstring': faultstring}

  def store_pending_buffer_cancellation(self, error='QuickCancel'):  
    """Storing the PendingBufferCancellation so we can send the CFDI to the SAT later
    """

    success = False
    try:
      next_attempt = datetime.now() + timedelta(minutes=settings.SAT_PENDINGBUFFER_INTERVAL)
      for uuid in self.uuids:
        pending_buffer = PendingBufferCancellation(
          taxpayer_id = self.taxpayer_id,
          uuid = uuid,
          next_attempt = next_attempt,
          type = self.type,
          error = error,
          certificate = self.user_certificate,
          key = self.user_key,
          passphrase = self.user_passphrase
        )
        if self.reseller is not None:
          pending_buffer.reseller = self.reseller
        pending_buffer.save()

        # After sending the pending_buffer process it with pending_celery_cancellation
        pending_celery_cancellation.delay(pending_buffer)
        success = True
    except:
      pass

    return success

class Registration(object):
  
  def __init__(self, reseller, taxpayer_id):
    self.reseller = reseller
    self.reseller_type = reseller.type
    self.taxpayer_id = taxpayer_id
    self.is_valid = False
  
  def add(self, coupon=None, added=None):
    """add the user under the authenticated reseller account"""    
    try:

      from apps.invoicing.models import Client
      from apps.invoicing.models import Address
      from apps.invoicing.models import Account

      profile = self.reseller.profile
      account = Account.objects.get(id=profile.account_id)
      address = Address(
          country='M\xc3\xa9xico',
          state='Aguascalientes',
      )
      address.save()
      client = Client(
          account=account,
          name='',
          last_name='',
          second_last_name='',
          curp='',
          person_type=len(self.taxpayer_id)==13,
          email=self.reseller.username,
          taxpayer_id=self.taxpayer_id,
          address=address,
      )
      client.save()

      if self.reseller_type == 'U':
        reseller_user, created = ResellerUser.objects.get_or_create(reseller=self.reseller, taxpayer_id=self.taxpayer_id)      
        if coupon is not None and self.reseller.coupon_allowed:
          reseller_user.coupon = coupon
          reseller_user.status = 'P'
          if added is not None:
            added = added[:19]
            created = datetime.strptime(added, '%Y-%m-%d %H:%M:%S')
            if type(created) is datetime:
              reseller_user.save()
              reseller_user.created = added
        reseller_user.save()
      if self.reseller_type == 'I':
        reseller_user_invoice, created = ResellerUserInvoice.objects.get_or_create(reseller=self.reseller, taxpayer_id=self.taxpayer_id, counter=0)
        reseller_user_invoice.save()       
      if created:
        return True, "Account Created successfully"
      return True, "Account Already exists"
    except Exception,e:
      print str(e)
      pass

    return False, "There was an error registering the User"        

  def edit(self, status):
    """edit the user under the authenticated reseller account"""

    from wis.apps.services.models import RESELLERUSER_STATUS
    valid_status = False
    if status in ('A', 'S'):
      valid_status = True

    if valid_status:
      try:
        if self.reseller_type == 'U':
          reseller_user = ResellerUser.objects.get(reseller=self.reseller, taxpayer_id=self.taxpayer_id)
        if self.reseller_type == 'I':
          reseller_user = ResellerUserInvoice.objects.get(reseller=self.reseller, taxpayer_id=self.taxpayer_id)
        reseller_user.status = status
        reseller_user.save()
      except:
          return False, "User does not exists"      
    else:
      return False, "Invalid Status for the User"

    if status == 'S':  
      message = "Account was Suspended successfully"    
    elif status == 'A':  
      message = "Account was Activated successfully"

    return True, message

  def delete(self):
    """delete the user under the authenticated reseller account"""
    try:
      if self.reseller_type == 'U':
        reseller_user = ResellerUser.objects.get(reseller=self.reseller, taxpayer_id=self.taxpayer_id)      
      if self.reseller_type == 'I':
        reseller_user = ResellerUserInvoice.objects.get(reseller=self.reseller, taxpayer_id=self.taxpayer_id)      
      # Validate the billing info of the User so we can delete it or not
      # status = 'A' and counter = '0' ??
      reseller_user.delete()
    except:
      return False, "There User does not exists, couldn't be deleted"
    return True, "Account Deleted successfully"

class LCO(object):
  
  def __init__(self, taxpayer_id, certificate_number=None):
    
    self.taxpayer_id = taxpayer_id
    self.certificate_number = certificate_number
  
  def check_lco(self):
    lco_obj = None
    try:
      lco_obj = lco.objects.filter(rfc=self.taxpayer_id)
      if lco_obj is not None and len(lco_obj):
        return True
    except:
      pass
    return False

  def valid(self):
    lco_dict = {}
    lco_obj = None
    result = False
    message = _('This certificate is not on the LCO list')

    try:
      lco_obj = lco.objects.get(rfc=self.taxpayer_id, certificate_number=self.certificate_number)
      if lco_obj is not None:
        lco_start = datetime.strptime(lco_obj.start_date,'%Y-%m-%dT%H:%M:%S')
        lco_final = datetime.strptime(lco_obj.final_date,'%Y-%m-%dT%H:%M:%S')

        result = True
        message =_('OK')
        
        if not (lco_start < datetime.now()):
          result = False
          message =_('This CSD could not be used yet')

        if not(datetime.now() < lco_final):          
          result = False
          message = _('This CSD has expired and could not be used')
          
        if not int(lco_obj.validity_obligation)>0:          
          result = False
          message = _('This CSD has not Validity Obligation or has been revoked')
        
        if lco_obj.certificate_status == 'C':
          result = False
          message = _('This CSD has expired')
        
        if lco_obj.certificate_status == 'R':
           result = False
           message = _('This CSD has been  revoked')
    except:
      pass

    lco_dict = {'result': result, 'message': message}
    return lco_dict

class CancellationReceipt(object):

  def __init__(self, taxpayer_id=None, uuid='', user=None):
    self.taxpayer_id = taxpayer_id
    self.uuid = uuid
    self.user = user
    self.reseller = None
    if self.user.get_profile().role == 'R':
      self.taxpayer_id = self.user.get_profile().account.taxpayer_id
    else:
      self.reseller = Reseller.objects.get(profile=self.user.get_profile())

  def get_receipt(self, type='C'):
    result = {'success':False, 'xml':'', 'message': 'Could not get receipt'}
    try:
      if type == 'C':        
        if self.reseller is not None:
          try:
            # Make sure the reseller has access to that uuid, taxpayer_id
            reseller_cancellation = ResellerCancellation.objects.filter(reseller=self.reseller, uuid=self.uuid, taxpayer_id=self.taxpayer_id).order_by('-date')
          except:
            return {'success':False, 'xml':'', 'message': 'There is not a Cancellation receipt with that info'}
        cancellation = SATCancellation.objects.filter(taxpayer_id=self.taxpayer_id, uuid=self.uuid).order_by('-date')
        if len(cancellation):
          cancel_obj = cancellation[0]
          result = {
            'success'     : True, 
            #'xml'         : receipt.xml, 
            'xml'         : cgi.escape(cancel_obj.xml, quote=None),
            'message'     : 'OK', 
            'taxpayer_id' : self.taxpayer_id, 
            'uuid'        : self.uuid, 
            'date'        : cancel_obj.date
          }
        else:
          result = {'success':False, 'xml':'', 'message': 'There is not a Cancellation receipt with that info'}
      else:
        if self.reseller is not None:
          try:
            # Make sure the reseller has access to that uuid, taxpayer_id
            reseller_invoice = ResellerInvoice.objects.filter(reseller=self.reseller, uuid=self.uuid, taxpayer_id=self.taxpayer_id).order_by('-date')
          except:
            return {'success':False, 'xml':'', 'message': 'There is not a Receipt receipt with that info'}
        receipts = Receipt.objects.filter(taxpayer_id=self.taxpayer_id, uuid=self.uuid).order_by('-date')
        if len(receipts):
          receipt = receipts[0]
          result = {
            'success'     : True, 
            #'xml'         : receipt.xml, 
            'xml'         : cgi.escape(receipt.xml, quote=None),
            'message'     : 'OK', 
            'taxpayer_id' : self.taxpayer_id, 
            'uuid'        : self.uuid, 
            'date'        : receipt.date
          }
        else:
          result = {'success':False, 'xml':'', 'message': 'There is not a Receipt with that info'}
    except:
      result = {'success':False, 'xml':'', 'message': 'There was an error getting the Receipt'}

    return result


class QueryPending(object):

  def __init__(self, uuid, user=None):
    self.uuid = uuid
    self.user = user
    self.is_valid = True

  def get_invoice(self, type='R'):
    result = {'success':False, 'xml':'', 'message': 'Could not get invoice'}
    if type == 'R':
      if self.user.get_profile().role == 'S':
        try:
          reseller = Reseller.objects.get(profile=self.user.get_profile())
          invoice = ResellerInvoice.objects.get(reseller=reseller, uuid=self.uuid)
        except:
          return result
      else:
        try:
          invoice = Invoice.objects.get(uuid=self.uuid)
        except:
          return result

      result = {
        'success': True, 
        'error': '', 
        'attempts': '0', 
        'status': invoice.status,             
        'uuid': invoice.uuid, 
        'date': str(invoice.date),
        'next_attempt': ''
      }

      try:
        pending_obj = PendingBuffer.objects.get(uuid=self.uuid)        
        if invoice.status == 'S':
            result['error'] = pending_obj.error
            result['attempts'] = str(pending_obj.attempts)
            result['next_attempt'] = str(pending_obj.next_attempt)            
        else:
            result['xml'] = cgi.escape(invoice.xml.encode('utf-8'), quote=None)
            #result['original_string'] = invoice.original_string
            #result['cfdi_seal'] = invoice.cfdi_seal
      except:
        if invoice.status == 'F':
          result['xml'] = cgi.escape(invoice.xml.encode('utf-8'), quote=None)
          #result['original_string'] = invoice.original_string
          #result['cfdi_seal'] = invoice.cfdi_seal        
                    
    if type == 'C':
      result = {
        'success': True, 
        'error': '', 
        'attempts': '0', 
        'status': 'F',
        'uuid': self.uuid,
        'next_attempt': ''
      }

      try:
        pending_obj = PendingBufferCancellation.objects.filter(uuid=self.uuid).order_by('-date')[0]
        result['error'] = pending_obj.error
        result['attempts'] = str(pending_obj.attempts)
        result['next_attempt'] = str(pending_obj.next_attempt)
        return result
      except:
        pass

      try:
        invoice_cancellation = SATCancellation.objects.filter(uuid=self.uuid).order_by('-date')[0]
        result['uuid_status'] = invoice_cancellation.uuid_status
        result['date'] = str(invoice_cancellation.date)
        result['xml'] = invoice_cancellation.xml
        if int(invoice_cancellation.uuid_status) in (201,202):
          result['status'] = 'C'
      except:
        #result = {'success': True, 'attempts':0, 'uuid':self.uuid, 'status':False, 'error': 'UUID does not exist'}
        result['status'] = 'False'
        result['error'] = 'UUID does not exist'

    return result

class Stamped:
  """This class is responsible of providing the stamp information of an invoice
  """

  is_valid = False
  original_string = ""
  
  
  def __init__(self, xml, user):
    """This is the normal flow of validation of each of the errors 
       mentioned by the SAT and are within diagram validation
    """
    self.is_valid = True
    self.xml_string = xml
    self.user = user
    self.incident_list = []

    try:
      self.xml_etree = etree.fromstring(self.xml_string.encode('utf-8'))
    except:
      #self.xml_etree = etree.fromstring(self.xml_string.decode('utf-8')) # ???
      self.xml_etree = etree.fromstring(self.xml_string)

    self.result = self.signing_node_exist()
     
  def signing_node_exist(self):
    """Validate if the signing node exist
    """
    response = None
    try:
      signing_node_exist = SigningNodeExist(self.xml_etree)
      result = signing_node_exist.is_valid()
      if not result["success"]:
        self.is_valid = True
        if signing_node_exist.receipt is not None:
          reseller_invoice = ResellerInvoice.objects.get(uuid=signing_node_exist.receipt.uuid)
          # Fix for ResellerInvoices that don't have the xml
          if int(reseller_invoice.id) <= 438:
            from xml.dom import minidom
            try:
              self.xml_root = self.xml_etree
              self.xml_string = etree.tostring(self.xml_etree, encoding='UTF-8')
              if self.xml_etree.find(XML_INVOICE_NAMESPACE % "Complemento") is None:
                self.xml_root.append(etree.Element(XML_INVOICE_NAMESPACE % "Complemento"))
                self.xml_string = etree.tostring(self.xml_root, encoding='UTF-8')
              self.cfd_seal = self.xml_root.get("sello")
              unique_id = reseller_invoice.uuid
              stamping_date_str = reseller_invoice.date.strftime('%Y-%m-%dT%H:%M:%S')[:19]
              sat_seal = reseller_invoice.cfdi_seal
              try:
                xmldoc = minidom.parseString(self.xml_string.encode('utf-8'))
              except:
                xmldoc = minidom.parseString(self.xml_string)
              complementNode = xmldoc.getElementsByTagName('cfdi:Complemento')[0]
              tfd = xmldoc.createElement('tfd:TimbreFiscalDigital')
              tfd.setAttribute('xmlns:tfd', 'http://www.sat.gob.mx/TimbreFiscalDigital')
              tfd.setAttribute('xsi:schemaLocation', 'http://www.sat.gob.mx/TimbreFiscalDigital http://www.sat.gob.mx/sitio_internet/TimbreFiscalDigital/TimbreFiscalDigital.xsd')
              tfd.setAttribute('selloCFD', self.cfd_seal)
              tfd.setAttribute('FechaTimbrado', stamping_date_str)
              tfd.setAttribute('UUID', unique_id)
              tfd.setAttribute('noCertificadoSAT', settings.WIS_SAT_CERT)
              tfd.setAttribute('version', '1.0')
              tfd.setAttribute('selloSAT', sat_seal)          
              complementNode.appendChild(tfd)
              self.xml_string = xmldoc.toxml("utf-8")
              reseller_invoice.xml = self.xml_string
              reseller_invoice.save()
            except:
              pass
          # endFix

          response = {
            'UUID': signing_node_exist.receipt.uuid,
            'xml':  reseller_invoice.xml,
            'CodEstatus': signing_node_exist.receipt.cod_status,
            'Fecha': signing_node_exist.receipt.date,
            'NoCertificadoSAT': signing_node_exist.receipt.certificate_number,  
            'SatSeal': reseller_invoice.cfdi_seal,
          }
        elif signing_node_exist.pending_buffer is not None:
          # The invoice is still in the pendingbufffer
          reseller_invoice = ResellerInvoice.objects.get(uuid=signing_node_exist.pending_buffer.uuid)
          # Fix for ResellerInvoices that don't have the xml and is still at PendingBuffer
          if reseller_invoice.xml == '' and int(reseller_invoice.id) <=438:
            from xml.dom import minidom
            try:
              self.xml_root = self.xml_etree
              self.xml_string = etree.tostring(self.xml_etree, encoding='UTF-8')
              if self.xml_etree.find(XML_INVOICE_NAMESPACE % "Complemento") is None:
                self.xml_root.append(etree.Element(XML_INVOICE_NAMESPACE % "Complemento"))
                self.xml_string = etree.tostring(self.xml_root, encoding='UTF-8')
              self.cfd_seal = self.xml_root.get("sello")
              unique_id = reseller_invoice.uuid
              stamping_date_str = reseller_invoice.date.strftime('%Y-%m-%dT%H:%M:%S')[:19]
              sat_seal = reseller_invoice.cfdi_seal
              try:
                xmldoc = minidom.parseString(self.xml_string.encode('utf-8'))
              except:
                xmldoc = minidom.parseString(self.xml_string)
              complementNode = xmldoc.getElementsByTagName('cfdi:Complemento')[0]
              tfd = xmldoc.createElement('tfd:TimbreFiscalDigital')
              tfd.setAttribute('xmlns:tfd', 'http://www.sat.gob.mx/TimbreFiscalDigital')
              tfd.setAttribute('xsi:schemaLocation', 'http://www.sat.gob.mx/TimbreFiscalDigital http://www.sat.gob.mx/sitio_internet/TimbreFiscalDigital/TimbreFiscalDigital.xsd')
              tfd.setAttribute('selloCFD', self.cfd_seal)
              tfd.setAttribute('FechaTimbrado', stamping_date_str)
              tfd.setAttribute('UUID', unique_id)
              tfd.setAttribute('noCertificadoSAT', settings.WIS_SAT_CERT)
              tfd.setAttribute('version', '1.0')
              tfd.setAttribute('selloSAT', sat_seal)          
              complementNode.appendChild(tfd)
              self.xml_string = xmldoc.toxml("utf-8")
              reseller_invoice.xml = self.xml_string
              reseller_invoice.save()
            except:
              pass
          # endFix
          response = {
            'UUID': reseller_invoice.uuid,
            'xml':  reseller_invoice.xml,
            'CodEstatus': 'Comprobante timbrado satisfactoriamente',
            'Fecha': reseller_invoice.date.strftime("%Y-%m-%d %H:%M:%S"),
            'NoCertificadoSAT': settings.WIS_SAT_CERT,  
            'SatSeal': reseller_invoice.cfdi_seal,
          }
      else:
        pprint.pprint("Factura no ha sido timbrada")
        incident = SoapError(self.xml_string,603).fault()
        self.incident_list.append(incident)
        self.is_valid = False
    except Exception, e:
      # Fix for invoices present at the services_resellerinvoice_10_1 table
      try:
        from django.db import connection
        cursor = connection.cursor()
        invoice_sql = "SELECT * FROM services_resellerinvoice_10_1 WHERE uuid='%s'" % signing_node_exist.receipt.uuid
        cursor.execute(invoice_sql)
        invoice_row = cursor.fetchone()
        reseller = Reseller.objects.get(id=invoice_row[1])

        reseller_invoice = ResellerInvoice(
          reseller = reseller,
          uuid = invoice_row[2],
          taxpayer_id =  invoice_row[3],
          xml =  invoice_row[5],
          original_string =  invoice_row[6],
          cfdi_seal =  invoice_row[7],
          status =  invoice_row[8]
        )
        from xml.dom import minidom

        self.xml_root = self.xml_etree
        self.xml_string = etree.tostring(self.xml_etree, encoding='UTF-8')

        if self.xml_etree.find(XML_INVOICE_NAMESPACE % "Complemento") is None:
          self.xml_root.append(etree.Element(XML_INVOICE_NAMESPACE % "Complemento"))
          self.xml_string = etree.tostring(self.xml_root, encoding='UTF-8')

        self.cfd_seal = self.xml_root.get("sello")
        unique_id = reseller_invoice.uuid
        stamping_date_str = str(invoice_row[4])[:19]
        sat_seal = reseller_invoice.cfdi_seal
        
        try:
          xmldoc = minidom.parseString(self.xml_string.encode('utf-8'))
        except:
          xmldoc = minidom.parseString(self.xml_string)
        complementNode = xmldoc.getElementsByTagName('cfdi:Complemento')[0]

        tfd = xmldoc.createElement('tfd:TimbreFiscalDigital')
        tfd.setAttribute('xmlns:tfd', 'http://www.sat.gob.mx/TimbreFiscalDigital')
        tfd.setAttribute('xsi:schemaLocation', 'http://www.sat.gob.mx/TimbreFiscalDigital http://www.sat.gob.mx/sitio_internet/TimbreFiscalDigital/TimbreFiscalDigital.xsd')
        tfd.setAttribute('selloCFD', self.cfd_seal)
        tfd.setAttribute('FechaTimbrado', stamping_date_str)
        tfd.setAttribute('UUID', unique_id)
        tfd.setAttribute('noCertificadoSAT', settings.WIS_SAT_CERT)
        tfd.setAttribute('version', '1.0')
        tfd.setAttribute('selloSAT', sat_seal)          

        complementNode.appendChild(tfd)
        self.xml_string = xmldoc.toxml("utf-8")
        reseller_invoice.xml = self.xml_string
        reseller_invoice.save()

        response = {
          'UUID': signing_node_exist.receipt.uuid,
          'xml':  reseller_invoice.xml,
          'CodEstatus': signing_node_exist.receipt.cod_status,
          'Fecha': signing_node_exist.receipt.date,
          'NoCertificadoSAT': signing_node_exist.receipt.certificate_number,  
          'SatSeal': reseller_invoice.cfdi_seal,
        }

        return response
      except:
        pass

      pprint.pprint(e)
      incident = SoapError(self.xml_string,603).fault()
      self.incident_list.append(incident)
      self.is_valid = False
    if settings.WIS_AVOID_WS_VALIDATORS:
      self.is_valid = True 
    return response


class QR:
  """This class is responsible of generate the QR image of and UUID
  """

  is_valid = False
  
  def __init__(self, uuid, user, extension='PNG'):
    """This is the normal flow of validation of each of the errors 
       mentioned by the SAT and are within diagram validation
    """
    self.is_valid = False
    self.uuid = uuid
    self.user = user

    if extension.upper() in ('PNG', 'BMP', 'JPG', 'JPEG'):
      self.extension = extension.upper()
    else:
      self.is_valid = False
      self.error =  'Invalid Extension Type'
      return

    try:      
      if self.user.get_profile().role == 'S':
        self.reseller = Reseller.objects.get(profile=self.user.get_profile())
        invoice = ResellerInvoice.objects.get(reseller=self.reseller, uuid=self.uuid)
        self.taxpayer_id = invoice.taxpayer_id
      else:
        self.taxpayer_id = self.user.get_profile().account.taxpayer_id
        invoice = Invoice.objects.get(taxpayer_id=self.taxpayer_id, uuid=self.uuid)
      self.xml = invoice.xml
      self.taxpayer = invoice.taxpayer_id
      try:
        self.parseXML()
        self.is_valid = True  
      except Exception,e:
        self.is_valid = False
        self.error = str(e)      
    except:
      self.error = "Error UUID no Encontrado"

  def parseXML(self):
    try:
      self.xml_etree = etree.fromstring(self.xml)
    except:
      self.xml_etree = etree.fromstring(self.xml.encode('utf-8'))

    self.client_taxpayer_id = self.xml_etree.find(XML_INVOICE_NAMESPACE % 'Receptor').get('rfc')
    self.total = float(self.xml_etree.get('total'))

  def generate_qr(self):    
    try:
      self.is_valid = False
      from qrencode import Encoder
      import StringIO
      total_str = "%0.6f" % self.total
      while len(total_str) < 17:
        total_str = '0%s' % total_str
      qr_data = "?re=%s&rr=%s&tt=%s&id=%s" % (self.taxpayer_id, self.client_taxpayer_id, total_str, self.uuid)
      qrchart = Encoder()
      qrchart = qrchart.encode(qr_data.encode('utf-8'), { 'width': 290, 'height':290 })
      output = StringIO.StringIO()
      qrchart.save(output, self.extension)
      qr_base64 = output.getvalue().encode("base64")
      self.qr_base64 = qr_base64
      output.close()
      self.is_valid = True
    except Exception, e:
      self.is_valid = False
      self.error = str(e)

    

class Utilities:
  """This class has many utility method required by the resellers
  """
  
  def __init__(self, user):
    self.is_valid = False
    self.user = user
    self.reseller = None
    self.taxpayer_id = None
    self.error = ''

    if self.user.get_profile().role == 'S':
      self.reseller = Reseller.objects.get(profile=self.user.get_profile())
    else:
      self.taxpayer_id = self.user.get_profile().account.taxpayer_id

  def get_xml(self, uuid, taxpayer_id):    
    if self.reseller:
      try:
        if self.reseller.type == 'I':
          reseller_user = ResellerUserInvoice.objects.get(reseller=self.reseller, taxpayer_id=taxpayer_id)
        elif self.reseller.type == 'U':
          reseller_user = ResellerUser.objects.get(reseller=self.reseller, taxpayer_id=taxpayer_id)
        try:
          reseller_invoice = ResellerInvoice.objects.get(uuid=uuid, reseller=self.reseller)
          self.xml = reseller_invoice.get_xml()
          self.is_valid = True
        except:
          self.error = 'UUID Does not Exists'
      except:
        self.error = 'Taxpayer ID Does not Exists'
    else:
      try:
        invoice = Invoice.objects.get(uuid=uuid, taxpayer_id=self.taxpayer_id)
        self.xml = invoice.xml
        self.is_valid = True
      except:
        self.error = 'UUID Does not Exists'

  def report_by_uuid(self, taxpayer_id, date_from=None, date_to=None):
    if self.reseller:
      try:
        reseller_invoices = ResellerInvoice.objects.filter(reseller=self.reseller, taxpayer_id=taxpayer_id)
        if date_from and date_to:
          reseller_invoices.filter(date__range=[date_from, date_to])
        self.invoices = reseller_invoices.values('uuid', 'date')
        self.is_valid = True
      except:        
        self.error = 'Taxpayer ID Does not Exists'
        self.is_valid = False
    else:
      try:
        invoices = Invoice.objects.filter(taxpayer_id=self.taxpayer_id)
        if date_from and date_to:
          invoices.filter(date__range=[date_from, date_to])
        self.invoices = invoices.values('uuid', 'date')
        self.is_valid = True
      except:        
        self.error = 'Taxpayer ID Does not Exists'
        self.is_valid = False

  def report_counter(self, taxpayer_id=None, date_from=None, date_to=None):
    if self.reseller:
      try:  
        self.result =  ResellerInvoice.objects.filter(reseller=self.reseller)
        if taxpayer_id:
          self.result = self.result.filter(taxpayer_id=taxpayer_id)
        if date_from and date_to:
          self.result = self.result.filter(date__range=[date_from, date_to])
        
        #self.result = ResellerInvoice.objects.filter(reseller=self.reseller).values('taxpayer_id').annotate(count=Count('taxpayer_id'))
        self.result = self.result.values('taxpayer_id').annotate(count=Count('taxpayer_id'))

        self.is_valid = True
      except Exception, e:
        self.is_valid = False
        self.error = str(e)
    else:
      try:
        count = Invoice.objects.filter(taxpayer_id=self.taxpayer_id).count()
        self.result = [{'taxpayer_id':self.taxpayer_id, 'count':count}]
        self.is_valid = True
      except Exception, e:
        self.is_valid = False
        self.error = str(e)







    
     
  
