# -*- coding: utf-8 -*-
from lxml import etree
from StringIO import StringIO
import M2Crypto
import datetime
import time
from django.utils import timezone
#from apps.invoicing.util import FileManager
#from apps.invoicing.util import pycripto_function_dec
import pprint
import hashlib
import base64
from django.utils.translation import ugettext as _
#from apps.sat.models import lco
import urllib
#from apps.invoicing.util import gen_digital_seal, gen_seal
from django.conf import settings
import chardet 
#from apps.services.models import Receipt
#from apps.services.models import PendingBuffer
import os
import uuid
from xml.dom import minidom

SAT_FILE_MANAGER = FileManager(valid_types=['octet-stream'])
    
    
XML_INVOICE_NAMESPACE = "{http://www.sat.gob.mx/cfd/3}%s"
XML_TFD_NAMESPACE = "{http://www.sat.gob.mx/TimbreFiscalDigital}%s"
XML_XSD_CFDI_VERSION = "3.2"
XML_XSD_CDF_NAME = "cfdv32.xsd"
XML_XSLT_CDF_NAME = "cadenaoriginal_3_2.xslt"

class AddExternalInvoice(object):
  """This class is responsible for adding the invoice in XML format
  """

  def __init__(self, invoice_dict, xml, user):    
    self.external_invoice_dict = invoice_dict
    self.xml = xml
    self.user = user
    if not self.invoice_exist():
      self.__get_account()
      self.__get_expedition_address()
      self.__create_or_exist_address_client()
      self.__create_or_exist_client()
      self.__create_or_exist_product()
      self.__create_or_exist_invoice()
      self.__create_or_exist_invoice_status()
      self.__create_or_exist_concepts()
    
    
  
  def invoice_exist(self):
   
    account = self.user.get_profile().account

    folio = 0
    try:
      folio = self.external_invoice_dict["comprobante"]["folio"]
    except :
      self.is_invoice = False
    invoice = Invoice.objects.filter(account=account, folio = folio)

    if len(invoice) > 0:
      self.is_invoice = True
    else:
      self.is_invoice = False
    return self.is_invoice


  def __get_account(self):
    self.account = self.user.get_profile().account
    
  def __get_expedition_address(self):
    self.expedition_address = self.account.address
  
  def __create_or_exist_address_client(self):
    dict = self.external_invoice_dict
    country, state = get_address_tuple(dict['domicilio']['pais'],dict['domicilio']['estado'])
    try:
      self.address = Address.objects.get_or_create(
        country = dict['domicilio']['pais'],
        state = state,
        municipality = dict['domicilio']['municipio'],
        locality = dict['domicilio']['localidad'],
        neighborhood = dict['domicilio']['colonia'],
        zipcode = dict['domicilio']['codigoPostal'],
        street = dict['domicilio']['calle'],
        external_number = dict['domicilio']['noInterior'],
        internal_number = dict['domicilio']['noExterior'],
        phone = '',
      )[0]
     
    except Exception,e:
      print e 
      
    try:
      self.address.save()
    except Exception, e :
      print e
  
  
  def __get_name(self,name):
    list = re.split(r"[' ']*", name, 0)
    if len(list) >3:
      name_list = [' '+ n for n in list[:-2]]
      name_list = ''.join(name_list).strip()
      pprint.pprint(name_list)
      last_name_list = list[-2:]
      name = {
        'name' : name_list,
        'last_name': last_name_list[0],
        'seccond_last_name' : last_name_list[1]
      }
      return name
    elif len(list) == 3:
      name = {
        'name' : list[0],
        'last_name' : list[1],
        'second_last_name' : list[2]
      }
      return name
    else:
      name = {
        'name' : list[0],
        'last_name' : list[1],
        'second_last_name' : ''
      }
      return name
    
  def __create_or_exist_client(self):
    dict = self.external_invoice_dict
    name = self.__get_name(dict['receptor']['nombre'])
    import pprint
    pprint.pprint(name)
    try:
      self.client = Client.objects.get_or_create(
        account = self.account,
        name = name['name'],
        last_name = name['last_name'],
        second_last_name = name['second_last_name'],
        taxpayer_id = dict['receptor']['rfc'],
        person_type = True if len(dict['receptor']['rfc']) == 13 else False,
        address = self.address,
        email = '',
        curp = '',
        is_live_connected = False,
        is_on_border = False
      )[0]
     
    except Exception, e :
      print e
     
    try:      
      self.client.save()
    except Exception, e:
      print e
      
      
  def __create_or_exist_product(self):
    dict = self.external_invoice_dict
    
    concepts = dict['conceptos']
    self.list_products = []
    for concept in concepts:
      product = ProdSvc.objects.get_or_create(
        account = self.account,
        type = 'P',
        name = 'Product',
        code = '',
        unit = concept['unidad'],
        price = float(concept['valorUnitario']),
        description = concept['descripcion'],
      )[0]
      
      try:
        product.save()
      except Exception,e:
        print e
        
      product_object = {
        'product' : product,
        'concept' : concept
      }
      self.list_products.append(product_object)
      
     
  def __create_or_exist_concepts(self):
        
    tax_dict = {
      "accounttaxes": [],
      "taxes": []
    }
    
    account_tax = AccountTax.objects.filter(account = self.account , status= True, tax__name = "IVA")
    for tax in account_tax:
      tax_dict['accounttaxes'].append(
        {
          "name": tax.tax.name, 
          "value": tax.tax.tax, 
          "tax_id": tax.tax.id
        }
      )

    for product in self.list_products:
      quantity = product['concept']['cantidad']
      quantity = int(quantity)
      unit_type = product['concept']['unidad']
      identification_number = product['concept']['noIdentificacion']
      description = product['concept']['descripcion']
      unit_price = float(product['concept']['valorUnitario'])
      amount = quantity * unit_price
      
      
      
      try:
        self.concept = Concept.objects.get_or_create(
          invoice = self.invoice,
          quantity = quantity,
          unit_type = unit_type,
          product_service = identification_number,
          description = description,
          unit_value = None,
          amount = amount,
          unit_price = unit_price,
          tax = tax_dict,
          discount = None,
          sku = None,
        )[0]
        
      except Exception, e:
        print e
    
      self.concept.save()
    
  def __create_or_exist_invoice(self):
   
    dict = self.external_invoice_dict
    try:
      total_retained_taxes = dict["impuestos"]["totalImpuestosRetenidos"]
      total_retained_taxes = float(total_retained_taxes)
    except Exception, e:
      total_retained_taxes = 0.0
    
    try: 
      total_transferred_taxes = dict["impuestos"]["totalImpuestosTrasladados"]
      total_transferred_taxes = float(total_transferred_taxes)
    except Exception, e:
      total_transferred_taxes = 0.0
    
    total_taxes = total_retained_taxes + total_transferred_taxes
    
    template = Template.get_current_template(self.account, 'I')
    
    currency = Currency.objects.filter(money_type="M.N.")[0]  
    
    subtotal = dict["comprobante"]["subtotal"]
    subtotal = float(subtotal)
    
    total = dict["comprobante"]["total"]
    total = float(total)
    
    serial = dict["comprobante"]["serie"]
    
    folio = dict["comprobante"]["folio"]
    
    uuid = dict["timbre"]["UUID"]
    
    template = Template.objects.filter(type ='I')[0]
    try:
      self.invoice = Invoice.objects.get_or_create(
        account = self.account,
        client = self.client,
        user = self.user,
        expedition_address = self.account.address,
        currency = currency,
        terms = '',
        subtotal = subtotal,
        discount = None,
        tax = total_taxes,
        total = total,
        internal_notes = '',
        external_notes = '',
        date = dict['comprobante']['fecha'],
        pay_date = dict['comprobante']['fecha'],
        paid_comment = '',
        type = 'I',
        tax_receipt_type = 'I',
        certificate_no = '',
        payment_status = False,
        serial = serial,
        folio = folio,
        snapshot = '',
        xml = self.xml,
        total_size = 1,
        uuid = uuid,
        
        template = template,
        # cfdi V3.2 FIELDS
        version = '3.2',
        payment_method = 'EFECTIVO',
        payment_way = 'E',
        discount_reason = '', 
        exchange_rate = '', 
        payment_conditions = '', 
        payment_account_number = '', #
        original_folio = None, 
        original_serial = None, 
        original_date = None, 
        original_amount = None, 
        
        sat_seal = '',
      )[0]
      
      
      self.invoice.paid_date = timezone.now()
      self.invoice.certification_date = timezone.now()
      self.invoice.snapshot = get_snapshot(request=None, expedition_address = self.expedition_address, invoice = self.invoice)
    except Exception, e:
      print e
    self.invoice.save()

  def __create_or_exist_invoice_status(self):
    self.invoice_status = InvoiceStatus( 
      user = self.user.get_profile(),
      invoice = self.invoice,
      date = timezone.now(),
      status = 'F'
    )  
    
    self.invoice_status.save() 
    

class CertificateExpiration(object):
  """This class is responsible for checking the expiration 
     date of the certification that the bill pem format which 
     belongs to the client
  """
  
  def __init__(self, xml_etree, x509_cert):
    #self.xml_root = xml_etree.getroot()
    self.xml_root = xml_etree
    self.cert = x509_cert
    self.valid = True
    self.error = ''

    try:
      self.date_after = x509_cert.get_not_after().get_datetime().replace(tzinfo=None)
      self.date_before = x509_cert.get_not_before().get_datetime().replace(tzinfo=None)
      self.date_node = self.xml_root.get("fecha")
      self.invoice_date = time.strptime(self.date_node,'%Y-%m-%dT%H:%M:%S')
      self.invoice_date = datetime.datetime(*self.invoice_date[0:6]).replace(tzinfo=None)
    except Exception as e:
      self.error = str(e)
      self.valid = False

  def is_valid(self):
    if self.valid and self.invoice_date >= self.date_before  and self.invoice_date <= self.date_after:      
      result = {
        "success" : True,
        "message" : "Issue date is within the certificate's validity date"
      }
    else:
      result = {
        "success" : False,
        "message" : "Issue date is not within the certificate's validity date"
      }
    print result
    return result
    
class CheckEncoding:
  
  def __init__(self, string):
    self.__char_detection(string)
    
  def is_valid(self):
    self.response = {
      "success" : self.is_utf8,
      "message": self.msg
    }
    return self.response 
    
  def __char_detection(self, string):
    detected = chardet.detect(string)  
    if detected["encoding"] == "utf-8":
      self.is_utf8 = True
      self.msg = _('The file is encoding in utf-8')
    else:
      self.is_utf8 = False
      self.msg = _('The file is not encoding in utf-8 is in %s'%detected["encoding"])
 
 
class ContentValidator():
  """ It is responsible for validating the xml document 
      in regard to concepts and taxes nodes
  """
  
  def __init__(self,path):
    self.path = StringIO(path)
  
        
  def concepts(self):
    parser = etree.parse(self.path)
    element = parser.find(XML_INVOICE_NAMESPACE % 'Conceptos')
    elements = element.getchildren()
    
    concepts = {
      'concepts' : [],
      'valid' : True
    }
    total_concepts = 0.0
    for element in elements:
      quantity = float(element.get('cantidad'))
      unit_price = float(element.get('valorUnitario'))
      total = quantity * unit_price
      total_cfdi = float(element.get('importe'))
      total_concepts += total_cfdi
      is_valid = total == total_cfdi
      
      concept = {
        'is_valid' : is_valid,
        'total' : total_cfdi,
        'description' : element.get('descripcion'),
        'identification_number' : element.get('noIdentificacion'),
        'cantidad' : element.get('cantidad'),
        'importe' : element.get('importe'),
        'valor_unitario' : element.get('valorUnitario')
        
      }
      if not is_valid:
        # Concepts invalid detected
        concepts["valid"] = is_valid
      concepts['concepts'].append(concept)
    concepts['total'] = total_concepts
    return concepts
    
       
  
  def get_root_attributes(self):
    parser = etree.parse(self.path)
    root_tag = parser.getroot()
    keys = root_tag.keys()
    attributes = {}
    for key in keys:
      attributes[key] = root_tag.get(key)
    return attributes
    
  
  def get_total_taxes_transferred(self):
    try:
      parser = etree.parse(self.path)
      element = parser.find(XML_INVOICE_NAMESPACE %'Impuestos')
      return float( element.get('totalImpuestosTrasladados') )
      
    except Exception:
      return 0.0
      

  def get_total_taxes_retained(self):
    try:
      parser = etree.parse(self.path)
      element = parser.find(XML_INVOICE_NAMESPACE %'Impuestos')
      return float( element.get('totalImpuestosRetenidos') )
    except Exception:
      return  0.0
      
    
  def concepts_are_valid(self):
    try:
      receipt = self.get_root_attributes()
      concepts = self.concepts()
      taxes = {}
      taxes['totalImpuestosTrasladados'] = round(self.get_total_taxes_transferred(),2)
      taxes['totalImpuestosRetenidos'] = round(self.get_total_taxes_retained(),2)
      total = float(concepts['total']) + \
            taxes['totalImpuestosTrasladados'] + \
            taxes['totalImpuestosRetenidos']
      total = round(total,2)
      
      total_root_xml = float(receipt['total'])
      total_root_xml = round(total_root_xml,2)
      valid = total == total_root_xml

      valid = concepts["valid"]
      if valid:
        msg = _("The concepts in the invoice are valid")
      else: 
        msg = _("The concepts in the invoice are not valid")
      data = {
        "success" : valid,
        "message" : msg,
        "extra_info" : self.get_extra_info_concepts(concepts)
      }
      
      return data
    except Exception, e:
      data = {
        "success" : False,
        "message" : str(e)
      }
      
      
  def taxes_are_valid(self):
    
      """
      @todo: Remove the negative sign in the invoice
      @autor: Eduardo Lujan
      """
      retained_taxes_list = self.get_retained_taxes()
      total_retained_taxes = 0.0
      for tax in retained_taxes_list:
        total_retained_taxes +=  float(tax['importe']) * (-1.0)
        total_retained_taxes = round(total_retained_taxes,3) 
      
      transferred_taxes_list = self.get_transferred_taxes()
      total_transferred_taxes = 0.0
      for tax in transferred_taxes_list:
        total_transferred_taxes +=  float(tax['importe']) * (1.0)
        total_transferred_taxes = round(total_transferred_taxes,3)
      
      parser = etree.parse(self.path)
      element = parser.find(XML_INVOICE_NAMESPACE % 'Impuestos')
      
      xml_total_retained_taxes = float(element.get("totalImpuestosRetenidos")) \
                     if element.get("totalImpuestosRetenidos") \
                     else 0.0
      xml_total_transferred_taxes = float(element.get("totalImpuestosTrasladados")) \
                      if element.get("totalImpuestosTrasladados") \
                      else 0.0
      valid_total_retained = xml_total_retained_taxes == total_retained_taxes
      valid_total_transferred = xml_total_transferred_taxes == total_transferred_taxes
      if valid_total_retained and valid_total_transferred:
        data = {
          "success" : True,
          "message" : [
            _(u"Taxes retained are valid"),
            _(u"Taxes transferred are valid"),
          ],
        }
      else:
        data = {
          "success" : False,
          "message" : [
            _(u"Taxes retained are %s" %   (_(u"valid") 
            if valid_total_retained else _(u"invalid"))),
            _(u"Taxes transferred are %s" % (_(u"valid") \
            if valid_total_transferred else _(u"invalid"))),
          ],
        }
      return data

    
  
  def get_retained_taxes(self):
    try:
      parser = etree.parse(self.path)
      element = parser.find(XML_INVOICE_NAMESPACE % 'Impuestos')\
              .find(XML_INVOICE_NAMESPACE % 'Retenciones')
      elements = element.getchildren()
      
      retained_taxes = []
      for element in elements:
        retained_dict = {}
        retained_dict["importe"] = element.get("importe")
        
        retained_dict["tasa"] = element.get("tasa") if not element.get else 0.0
        retained_dict["impuesto"] = element.get("impuesto")
        retained_taxes.append(retained_dict)
      return retained_taxes
    except Exception:
      return []


  def get_transferred_taxes(self):
    try:
      parser = etree.parse(self.path)
      element = parser.find(XML_INVOICE_NAMESPACE % 'Impuestos')\
              .find(XML_INVOICE_NAMESPACE % 'Traslados')
      elements = element.getchildren()
      
      transferred_taxes = []
      for element in elements:
        transferred_dict = {}
        transferred_dict["importe"] = element.get("importe")
        transferred_dict["tasa"] = element.get("tasa") if not element.get else 0.0
        transferred_dict["impuesto"] = element.get("impuesto")
        transferred_taxes.append(transferred_dict)
        return transferred_taxes
    except Exception:
      return []   
      


  def get_extra_info_concepts(self, concepts):
    return concepts
  
  
class DateValidator(object):

  def __init__(self, xml_etree):
    try:
      #self.xml_root = xml_etree.getroot()
      self.xml_root = xml_etree
      self.date_node = self.xml_root.get("fecha")
    except:
      self.date_node = "2012-01-01T00:00:00"
      
  def is_valid(self):
    invoice_date = time.strptime(self.date_node,'%Y-%m-%dT%H:%M:%S')
    invoice_compare =  time.strptime("2012-01-01T00:00:00","%Y-%m-%dT%H:%M:%S")
    if invoice_date >= invoice_compare:
      result = {
        "success" : True,
        "message" : "The issuance date is after the first of January of 2012"
      }
    else:
      result = {
        "success" : False,
        "message" : "The issuance date is not before the first of January 2012"
      }
    print result
    return result
    
    
class EmissionHoursValidator(object):
  """This class is responsible for validating the time of issuance 
     of the invoice in xml format to validate if belated or within 72 hours
  """
  
  def __init__(self, xml_etree):
    self.valid = True
    self.error = ''
    try:
      #self.xml_root = xml_etree.getroot()
      self.xml_root = xml_etree
      self.date_node = self.xml_root.get("fecha")
      self.invoice_date = time.strptime(self.date_node,'%Y-%m-%dT%H:%M:%S')
      self.invoice_date = datetime.datetime(*self.invoice_date[0:6])
      self.today = timezone.now().replace(tzinfo=None)            
      self.delta_72hrs = datetime.timedelta(hours=72)
      self.date_range = self.today - self.delta_72hrs
    except Exception as e:
      self.error = str(e)
      self.valid = False
      self.date_node = "NOT AVAILABLE"
      
  def is_valid(self):
    if self.valid and self.invoice_date >= self.date_range and self.invoice_date <= self.today:
      result = {
        "success" : True,
        "message" : "The date range is not greater than 72 hours, Invoice date is %s" % self.invoice_date
      }
    else:
       result = {
        "success": False,
        'message': "The date range is greater than 72 hours, Invoice date is %s" % self.invoice_date
      }
    
    print result    
    return result
    
    
class FielValidator():
  """This class is responsible for validating whether a certificate is a 
     Fiel or a certificate
  """
  
  def __init__(self,xml_etree, x509_cert):
    self.valid = True
    self.error = ''
    try:
      #self.xml_root = xml_etree.getroot() 
      self.xml_root = xml_etree
      self.x509_cert = x509_cert
      subject = self.x509_cert.get_subject().__str__()
      if "OU" in subject:
        self.is_fiel = False
      else:
        self.is_fiel = True
    except Exception as e:
      self.valid = False
      self.error = str(e) 

  def is_valid(self):
    if self.valid  and not self.is_fiel:
      result = {
        "success" : True,
        "message" : "The issuer certificate is not of type FIEL"
      }
    else:
      result = {
        "success" : False,
        "message" : "The issuer certificate is of type FIEL"
      }
    pprint.pprint(result)
    return result

  
class InternalInvoiceValidator:
  """This class is responsible for validating the contents of an invoice 
     in xml format, validation ensures that the sum of the concepts and 
     taxes are well calculated  
  """
  def __init__(self, xml, user):
    print user
    self.xml = xml
    self.user = user
    self.list_messages = []
    self.__get_cert_from_string()
   


  def __get_cert_from_string(self):
    
    string = self.xml['comprobante']['certificado']
    split_string_cert = self.__split_cert_file(string,64)
    l = [x + "\n"for x in split_string_cert]
    split_string_cert = l
    split_string_cert = "".join(split_string_cert)
    split_string_cert = "-----BEGIN CERTIFICATE-----\n"+split_string_cert+"-----END CERTIFICATE-----"""
    self.cert = M2Crypto.X509.load_cert_string(split_string_cert)
    cert_subject = self.cert.get_subject().as_text()
    cert_subject = cert_subject.split('/')
    self.cert_dict  = {}
    for field in cert_subject:
      field = field.strip()
      field = field.split('=')
      if len(field) == 2:
        self.cert_dict[field[0].strip()] = field[1].strip() 
   


  def __split_cert_file(self,string_cert,length): 
    return [string_cert[i:i+length] for i in range(0, len(string_cert), length)]

  def is_cfd(self):
    """
    Validation Service that allows the certificate is authorized by the SAT,
    which corresponds to the RFC of the emitter and the date of emitter is 
    analyzed within the period of validity. 
    When this validation is successful, we can be sure that the issuer of
    the voucher is authorized by the SAT to issue CFD / CFDI
    """
    if not self.__get_dates_valid_from_csd():
      return False
    
    return True
    
    
  def __get_matches_from_csd_file(self):
    
      file_manager = FileManager()
      f = file_manager.open('ftp_sat_files/CSD.txt')
      csd = f.read()
      import re
      matches = re.findall(r"^.*"+self.cert_dict['x500UniqueIdentifier']+".*$",
                           csd,re.MULTILINE)
      list_matches = []
      keys = "no_serie|fec_inicial_cert|fec_final_cert|RFC|edo_certificado".split('|')
      for match in matches:
        csd_dict_match = {}
        strs =  match.split('|')
        index = 0
        for key in keys:
          csd_dict_match[key] = strs[index]
          index += 1  
        list_matches.append(csd_dict_match)
      return list_matches
   
  def __get_matches_from_folio_file(self):
    file_manager = FileManager()
    f = file_manager.open('ftp_sat_files/FoliosCFD.txt')
    csd = f.read()
    import re
    matches = re.findall(r"^.*"+self.cert_dict['x500UniqueIdentifier']+".*$",
                         csd,re.MULTILINE)
    list_matches = []
    keys = "RFC|NoAprobacion|AnoAprobacion|Serie|FolioInicial|FolioFinal".split('|')
    for match in matches:
      csd_dict_match = {}
      strs =  match.split('|')
      index = 0
      for key in keys:
        csd_dict_match[key] = strs[index]
        index += 1  
      list_matches.append(csd_dict_match)
    return list_matches
   
  def __get_dates_valid_from_csd(self):
    list_matches = self.__get_matches_from_csd_file()
    date_valid = False
    taxpayer_id = False
    for match in list_matches:
      date = {}
      date['start'] = time.strptime(match['fec_inicial_cert'], "%Y-%m-%d %H:%M:%S")
      date['end'] = time.strptime(match['fec_final_cert'], "%Y-%m-%d %H:%M:%S")
      date['xml'] = xml_time = self.xml['comprobante']['fecha'].timetuple()
      if xml_time >= date['start'] and xml_time <= date['end']:
        date_valid = True
      pprint.pprint(match)
    self.__get_folio_valid()
    return date_valid


  def __get_taxpayer_id_valid(self, taxpayer_id):
    return taxpayer_id ==  self.xml['emisor']['rfc']
    
  def __get_folio_valid(self):
    xml_folio = self.xml['comprobante']['folio']
    xml_folio = int(xml_folio)
    list_folio_matches = self.__get_matches_from_folio_file()
    valid_folio = False
    for folio in list_folio_matches:
      pprint.pprint(folio)
      initial_folio = folio['FolioInicial']
      initial_folio = int(initial_folio)
      final_folio = folio['FolioFinal']
      year_approval = time.strptime(folio['AnoAprobacion'], "%Y")
      xml_time = self.xml['comprobante']['fecha'].timetuple()
      final_folio = int(final_folio)
      if xml_folio >= initial_folio  and xml_folio<= final_folio and xml_time >= year_approval:
        valid_folio = True
    if not valid_folio:  
      if xml_time < year_approval:
        self.list_messages.append(_('The date of the issuance of the invoice is not valid'))
      if xml_folio >= initial_folio  and xml_folio<= final_folio:
        self.list_messages.append(_('The folio is not within range of SAT folios allowed'))
    return valid_folio
    

class InvoiceSigner:
  """
  Responsible for modifying the node TimbreFiscalDigital invoice xml document
  
  @autor: Eduardo Lujan
  """
  
  def __init__(self, xml_string):
    self.xml_string = xml_string
    self.init_parser()
    self.select_sign_node()
    
  
  
  def init_parser(self):
    self.parser= etree.XMLParser(ns_clean = True)
    self.tree = etree.parse(StringIO(self.xml_string), self.parser)
   
  
  def select_sign_node(self):
    #self.invoice_root_node = self.tree.getroot()
    self.invoice_root_node = self.tree
    etree.tostring(self.invoice_root_node,encoding='UTF-8')
    self.selected_node = self.invoice_root_node\
               .find(XML_INVOICE_NAMESPACE % "Complemento")\
               .find(XML_TFD_NAMESPACE % "TimbreFiscalDigital")
    return self.selected_node
  
  
  def sign_xml(self,original_string):
    sign = self.sign_connector(original_string)
    if not sign :
      sign = "" 
    self.selected_node.set("selloSAT",sign)
    self.xml_signed = StringIO()
    self.xml_representation_signed = etree.tostring(self.invoice_root_node,encoding='UTF-8')
    self.xml_signed.write(self.xml_representation_signed)
    
    

  def sign_connector(self,original_string):
    connector = Connector()
    content = connector.http_post_request({
      'data' : original_string
    })
    if content["success"]:
      return content['message']
    else:
      return None
  
  
  def encode_file_base64(self,xml_signed):
    encoded_string = base64.encodestring(xml_signed) 
    return encoded_string 
  
  def get_xml_invoice(self):
    if self.xml_representation_signed is not None:
      return self.xml_representation_signed
    else:
      return u''
    
    
class LCOCSDValidator(object):
  """This house has to verify that the certificate is valid by LCO list
  """
  def __init__(self, xml_etree, x509_cert):
    self.valid = True
    self.error = ''
    try:      
      #self.xml_root = xml_etree.getroot()
      self.xml_root = xml_etree
      self.x509_cert = x509_cert
      self.serial_number = hex(self.x509_cert.get_serial_number())[3:-1:2]

      self.node = self.xml_root.find(XML_INVOICE_NAMESPACE % "Emisor")
      self.rfc =  self.node.get("rfc")
      self.rfc_ascii = self.__to_ascii(self.rfc)

      self.lco_is_valid = False
      try:
        lco_obj = lco.objects.get(rfc=self.rfc_ascii, certificate_number=self.serial_number, certificate_status='A')
        self.lco_is_valid = True
      except Exception as e:
        self.error = str(e)
        try:
          lco_obj = lco.objects.get(rfc=self.rfc, certificate_number=self.serial_number, certificate_status='A')
          self.lco_is_valid = True
        except Exception as e:
          self.error = str(e)
          pass
    except Exception as e:
      self.valid = False
      self.error = str(e)
      
  def __to_ascii(self,string):
    stripped = [c if 0 < ord(c) < 127 else '&' for c in string]
    return ''.join(stripped)
  
  def is_valid(self):
    if self.valid and self.lco_is_valid:
      result = {
        "success" : True,
        "message" : "The emitter CSD has not been revoked"
      }
    else:
      result = {
        "success" : False,
        "message" : "The emitter CSD has been revoked"
      }
    print result
    return result
  
  
class LCOValidator(object):
  
  def __init__(self, xml_etree, x509_cert):
    self.valid = True
    self.error = ''
    self.lco_is_valid = False
    try:
      #self.xml_root = xml_etree.getroot() 
      self.xml_root = xml_etree
      self.x509_cert = x509_cert
      self.node = self.xml_root.find(XML_INVOICE_NAMESPACE % "Emisor")
      self.rfc =  self.node.get("rfc")
      self.serial_number = hex(self.x509_cert.get_serial_number())[3:-1:2]
      self.rfc_ascii = self.__to_ascii(self.rfc)
      try:
        lco_list = lco.objects.get(rfc=self.rfc_ascii, certificate_number=self.serial_number)
        self.lco_is_valid = True
      except Exception as e:
        self.error = str(e)
        try:
          lco_list = lco.objects.get(rfc=self.rfc, certificate_number=self.serial_number)
          self.lco_is_valid = True
        except Exception as e:
          self.error = str(e)
          self.lco_is_valid = False
    except Exception as e:
      self.valid = False
      self.error = str(e) 

  def __to_ascii(self,string):
    stripped = [c if 0 < ord(c) < 127 else '&' for c in string]
    return ''.join(stripped)      
  
  def is_valid(self):
    if self.valid and self.lco_is_valid:
      result = {
        "success" : True,
        "message" : "RFC issuer is in the regime of taxpayers"
      }
    else:
      result = {
        "success" : False,
        "message" : "RFC issuer is not in the regime of taxpayers"
      }
    print result
    return result
  
  
class SealValidator(object):
  
  def __init__(self, xml_etree, x509_cert, original_string):
    self.valid = True
    self.error = ''
    try:
      self.seal_is_valid = False

      self.xml_root = xml_etree
      self.x509_cert = x509_cert
      self.original_string = original_string

      self.sign = self.xml_root.get("sello")
      self.decoded_sign = base64.decodestring(self.sign)

      xml_string = etree.tostring(self.xml_root, encoding='UTF-8')      
      if self.original_string  is None or self.original_string == "":
        os_obj = OriginalString(xml_string)
        self.original_string = os_obj.get_original_string()

      rsa = self.x509_cert.get_pubkey().get_rsa()
      pubkey = M2Crypto.EVP.PKey()
      pubkey.assign_rsa(rsa)
      pubkey.reset_context(md='sha1')
      pubkey.verify_init()
      pubkey.verify_update(self.original_string)
      self.seal_is_valid = bool(pubkey.verify_final(self.decoded_sign)) 
    except Exception as e:
      self.valid = False
      self.error = str(e)  
   
  
  def is_valid(self):
    if self.valid and self.seal_is_valid:
      result = {
        "success" : True,
        "message" : "The seal is valid for this CFDI",
        "original_string" : self.original_string,
        "sign" : self.sign
      }
    else:
      result = {
        "success" : False,
        "message" : "The seal is not valid for this CFDI",
        "original_string" : self.original_string,
        "sign" : self.sign
      }
    print result
    return result
  
  
class SignedSATAuthority(object):
  
  def __init__(self, xml_etree, x509_cert):
    self.valid = True
    self.error = ''
    try:
      #self.xml_root = xml_etree.getroot()
      self.xml_root = xml_etree
      self.x509_cert = x509_cert

      self.issuer_dn = self.x509_cert.get_issuer().as_text(flags=(M2Crypto.m2.XN_FLAG_RFC2253 | M2Crypto.m2.ASN1_STRFLGS_UTF8_CONVERT )  )
      self.issuer_dn = self.issuer_dn.decode("utf8","ignore")
      sat_admin = u"Servicio de Administraci\C3\B3n Tributaria" 
      sat_rfc = u"SAT97070701NN3"
      
      self.issuer_is_valid = False
      if ( sat_admin in self.issuer_dn or sat_rfc in  self.issuer_dn ):
        self.issuer_is_valid = True

      self.ca_is_valid = False
      certs_path = os.path.join(os.path.dirname(__file__), "certs", "production")
      if settings.LOCALDEV:
        certs_path = os.path.join(os.path.dirname(__file__), "certs")

      for root_cert in os.listdir(certs_path):
        cert_flag = False
        if os.path.isfile(os.path.join(certs_path,root_cert)):
          try:
            ca_root = M2Crypto.X509.load_cert("%s/%s" % (certs_path, root_cert), M2Crypto.X509.FORMAT_DER)
            cert_flag = True
          except M2Crypto.X509.X509Error:
            ca_root = M2Crypto.X509.load_cert("%s/%s" % (certs_path, root_cert), M2Crypto.X509.FORMAT_PEM)
            cert_flag = True
          except:
            continue
          finally:
            if cert_flag and bool(self.x509_cert.verify(ca_root.get_pubkey())):
              self.ca_is_valid = True
              break
    except Exception as e:
      self.valid = False
      self.error = str(e)
     
  def is_valid(self):    
    if self.valid and self.ca_is_valid and self.issuer_is_valid:
      result = {
        "success" : True,
        "message" : "The issuer CSD has been signed by a Certificate Authority of the SAT"
      }
    else:
      result = {
        "success" : False,
        "message" : "The issuer CSD has not been signed by a Certificate Authority of the SAT"
      }
    print result
    return result
  

class OriginalString(object):

  def __init__(self, xml):
    self.xml_invoice = xml
    self.parse_xml()
    
  def parse_xml(self):
    try:
      import libxml2
      import libxslt
      import urllib2
      
      xslt_path = os.path.join(os.path.dirname(__file__),"")
      xslt_path = "%s/xslt/%s" % (xslt_path, XML_XSD_CFDI_VERSION)
      xslt_path_file = "%s/%s" % (xslt_path, XML_XSLT_CDF_NAME)
      xslt_complements_path = "%s/complementos" % xslt_path
      response = open(xslt_path_file)
      xslt = response.read()
      xslt = xslt.replace('{{XSLT_COMPLEMENTS_PATH}}', xslt_complements_path)
      styledoc = libxml2.parseMemory(xslt,len(xslt))
      style = libxslt.parseStylesheetDoc(styledoc)
      doc = libxml2.parseMemory(self.xml_invoice, len(self.xml_invoice))
      result = style.applyStylesheet(doc, None)
      self.original_string = str(result)
      self.original_string = self.original_string.replace('<?xml version="1.0" encoding="UTF-8"?>\n', '')
      self.original_string = self.original_string.replace('\n','')
      self.original_string = self.original_string.replace('&amp;', '&')
      self.original_string = self.original_string.replace('&quot;', '"')
      self.original_string = self.original_string.replace('&lt;', '<')
      self.original_string = self.original_string.replace('&gt;', '>')
      self.original_string = self.original_string.replace('&apos;', '´')
      self.original_string = self.original_string.strip()
      print self.original_string
      return self.original_string
    except Exception, e:
      pprint.pprint(e)
  
  def get_original_string(self):
    return self.original_string
  
  
class SigningNodeExist(object):
  
  def __init__(self,xml_etree=None):
    self.xml_root = xml_etree
   
  def exists_signing_node(self):
    self.taxpayer = self.xml_root.find(XML_INVOICE_NAMESPACE % "Emisor").get("rfc")
    self.seal = self.xml_root.get("sello")
    self.receipt = None
    receives = Receipt.objects.filter(taxpayer_id = self.taxpayer, cfdi_seal=self.seal, cod_status__contains="recibido" )
    if len(receives) >= 1:
      self.receipt = receives[0]
      return True
    pending_buffer = PendingBuffer.objects.filter(cfdi_seal=self.seal)
    if len(pending_buffer) >= 1:
      self.pending_buffer = pending_buffer[0]
      return True
       
    self.signing_node = None
    try:
      self.signing_node = self.xml_root.find(XML_INVOICE_NAMESPACE % "Complemento")
      self.signing_node = self.signing_node.find(XML_TFD_NAMESPACE % "TimbreFiscalDigital")
      if self.signing_node is not None:
        return True
    except Exception, e:
      pass
    return False
      
  def is_valid(self):
    exists_node = self.exists_signing_node()
    if not exists_node:
      result = {
       "success": True,
       "message" : "The signing node does not exist"
      }      
    else:
      result = {
       "success": False,
       "message" : "The signing node exists"
      }
    print result
    return result  
    
    
class Signing(object):
  
  def __init__(self, xml_etree, addenda):
    self.valid = False
    self.error = ''
    self.tfd_string = ''
    self.sat_seal = ''
    self.xml_string = ''
    self.uuid = None
    try:
      #self.xml_root = xml_etree.getroot()
      self.xml_root = xml_etree
      self.xml_string = etree.tostring(self.xml_root, encoding='UTF-8')

      if self.xml_root.find(XML_INVOICE_NAMESPACE % "Complemento") is None:
        self.xml_root.append(etree.Element(XML_INVOICE_NAMESPACE % "Complemento"))
        self.xml_string = etree.tostring(self.xml_root, encoding='UTF-8')
      
      self.cfd_seal = self.xml_root.get("sello")
      #self.cfd_seal = self.cfd_seal.strip()
      self.cfd_seal = self.cfd_seal.replace(' ','')
      unique_id = str(uuid.uuid4()).upper()

      stamping_date = timezone.now()
      stamping_date_str = stamping_date.strftime('%Y-%m-%dT%H:%M:%S')[:19]

      if unique_id:
        try:
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
          tfd_original_chain = '||1.0|%s|%s|%s|%s||' % (unique_id, stamping_date_str, self.cfd_seal, settings.WIS_SAT_CERT)
          
          sat_seal = gen_seal(tfd_original_chain)

          if sat_seal is None:
            raise Exception('selloSAT No pudo ser creado')

          tfd.setAttribute('selloSAT', sat_seal)          

          self.tfd_string = tfd.toxml("utf-8")
          self.pretty_tfd_string = tfd.toprettyxml("  ","\n","utf-8")
          self.sat_seal = sat_seal
          self.uuid = unique_id
          self.stamping_date_str = stamping_date_str

          complementNode.appendChild(tfd)
          self.xml_string = xmldoc.toxml("utf-8")

          if addenda is not None:
            self.addenda_str = etree.tostring(addenda, encoding='UTF-8')
            try:
              self.addenda = minidom.parseString(self.addenda_str.encode('utf-8'))
            except:
              self.addenda = minidom.parseString(self.addenda_str)
            xmldoc.documentElement.appendChild(self.addenda.documentElement)
    
          self.pretty_xml_string = xmldoc.toprettyxml("  ","\n","utf-8") 
          self.valid = True
        except Exception as e:
          self.error = str(e)
    except Exception, e:
      self.error = str(e)

  def is_valid(self):
    if self.valid and self.tfd_string != '' and self.sat_seal != '' and self.xml_string:
      result = {
        "success" : True,
        "message" : "The Invoice has been signed.",
        "tfd_string": self.tfd_string,
        "xml_string": self.xml_string
      }
    else:
      result = {
        "success" : False,
        "message" : self.error
      }
    print result
    return result

    

class SubjectDNValidator(object):
  
  def __init__(self, xml_etree, x509_cert):
    self.valid = True
    self.error = ''
    try:
      #self.xml_root = xml_etree.getroot()
      self.xml_root = xml_etree
      self.x509_cert = x509_cert

      self.issuer_dn = self.x509_cert.get_subject().as_text()
      self.issuer_dn = self.issuer_dn.decode("utf-8", "replace")

      self.node_emitter = self.xml_root.find(XML_INVOICE_NAMESPACE % "Emisor")
      self.rfc = self.node_emitter.get("rfc").decode("utf-8","replace")
      
    except Exception as e:
      self.valid = False
      self.error = str(e)
  
  
  def is_valid(self):   
    result = {
      "success" : False,
      "message" : "The issuer CSD not corresponds to RFC sender by proof comes as fiscal invoice"
    }
    try:
      test_rfc = self.rfc.replace(u'\xd1','N')
      
      test_issuer_dn = unicode(self.issuer_dn)
      test_issuer_dn = test_issuer_dn.replace(u'\\xD1','N').replace(u'\xD1', 'N')      
      
      if self.valid and (test_rfc in test_issuer_dn):
        result = {
          "success" : True,
          "message" : "The issuer CSD corresponds to RFC sender by proof comes as fiscal invoice"
        }
    except Exception, e:
      self.error = str(e)
      pass
    print result
    return result
    
    
class XMLInvoice:
  """
  Is responsible for extracting data from xml to an 
  object type python dictionary
  @author: Eduardo Lujan 
  """

  
  def __init__(self, xml_string):
    self.xml_string = xml_string
    self.read_invoice()
    self.get_root_invoice()
    
    
  def set_user(self, user):
    self.user = user
    
  def read_invoice(self):
    
    self.parser= etree.XMLParser(ns_clean = True)
    self.tree = etree.parse(StringIO(self.xml_string), self.parser)
    data = {
      'success' : True,
      'message' : '',
    }
    return data
  
    data = {
      'sucess' : False,
      'message' : ''
    }
      
    
  def get_root_invoice(self):
    self.root_invoice = self.tree.getroot()
  
  def get_dict_from_invoice_xml(self):
    self.invoce_original_string_dict = {}
    self.invoce_original_string_dict["comprobante"] = {}
    node = self.root_invoice
    
    """
    please dont translate it
    """
    
    """ 
    Tag: Comprobante 
    Getting the attributes from de xml and setting the correct format for
    the original string 
    """
    serial =  node.get("serie") if node.get("serie") is not None else u""
    
    folio = int(node.get("folio")) if node.get("folio") is not None else u""
    fecha = datetime.datetime.strptime(node.get("fecha"),'%Y-%m-%dT%H:%M:%S')
    tipoDeComprobante = node.get("tipoDeComprobante")
    if tipoDeComprobante:
      tipoDeComprobante = unicode(tipoDeComprobante)
    else:
      tipoDeComprobante = u""
    formaDePago = node.get("formaDePago")
    if formaDePago :
      formaDePago = unicode(formaDePago)
    else:
      formaDePago = u""
      
    condicionesDePago = node.get("condicionesDePago")
    if condicionesDePago:
      condicionesDePago = unicode(condicionesDePago)
    else:
      condicionesDePago = u""
      
    subTotal = node.get("subTotal")
    if subTotal:
      subtotal = float(subTotal)
    else:
      subtotal = 0.0
    descuento = node.get("descuento")
    if descuento:
      descuento = float(descuento)
    else:
      descuento = 0.0
    total = node.get("total")
    if total:
      total = float(total)
    else:
      total = 0.0
      
    certificado = node.get("certificado") 
    """ 
    Tag: Emisor 
    Getting the attributes from de xml and setting the correct format for
    the original string 
    """
    rfc = node.find(XML_SCHEMA_TAG % "Emisor").get("rfc")
    if rfc :
      rfc = unicode(rfc)
    else:
      rfc = u""
    
    nombre = node.find(XML_SCHEMA_TAG % "Emisor").get("nombre")
    if nombre:
      nombre = unicode(nombre)
    else: 
      nombre = u""
    
    """ 
    Tag: Domicio Fiscal 
    Getting the attributes from de xml and setting the correct format for
    the original string 
    """
    calle = node.find(XML_SCHEMA_TAG % "Emisor")\
        .find(XML_SCHEMA_TAG % "DomicilioFiscal").get("calle")
    if calle :
      calle = unicode(calle)
    else:
      calle = u""
    
    noExterior = node.find(XML_SCHEMA_TAG % "Emisor")\
           .find(XML_SCHEMA_TAG % "DomicilioFiscal").get("noExterior")
    if noExterior:
      noExterior = unicode(noExterior)
    else:
      noExterior = u""
      
    noInterior = node.find(XML_SCHEMA_TAG % "Emisor")\
           .find(XML_SCHEMA_TAG % "DomicilioFiscal").get("noInterior")
    if noInterior:
      noInterior = unicode(noInterior)
    else:
      noInterior = u""
    
    colonia = node.find(XML_SCHEMA_TAG % "Emisor")\
          .find(XML_SCHEMA_TAG % "DomicilioFiscal").get("colonia")
    if colonia:
      colonia = unicode(colonia)
    else:
      colonia = u""
      
    localidad = node.find(XML_SCHEMA_TAG % "Emisor")\
          .find(XML_SCHEMA_TAG % "DomicilioFiscal").get("localidad")
    if localidad:
      localidad = unicode(localidad)
    else:
      localidad = u""
      
    referencia = "Sin Referencia",# @todo: Get real information
    if referencia:
      referencia = unicode(referencia)
    else :
      referencia = u""
      
    municipio = node.find(XML_SCHEMA_TAG % "Emisor")\
          .find(XML_SCHEMA_TAG % "DomicilioFiscal").get("municipio")
    if municipio:
      municipio = unicode(municipio)
    else:
      municipio = u""
      
    estado = node.find(XML_SCHEMA_TAG % "Emisor")\
         .find(XML_SCHEMA_TAG % "DomicilioFiscal").get("estado")
    if estado:
      estado = unicode(estado)
    else:  
      estado = u""
    
    pais = node.find(XML_SCHEMA_TAG % "Emisor")\
         .find(XML_SCHEMA_TAG % "DomicilioFiscal").get("pais")
    if pais:
      pais = unicode(pais)
    else:
      pais = u""
    
    codigoPostal = node.find(XML_SCHEMA_TAG % "Emisor")\
             .find(XML_SCHEMA_TAG % "DomicilioFiscal").get("codigoPostal")
    if codigoPostal:
      codigoPostal = unicode(codigoPostal)
    else:
      codigoPostal = u""
    
    
    """ 
    Tag: Expedido en 
    Getting the attributes from de xml and setting the correct format for
    the original string 
    """
    calle = node.find(XML_SCHEMA_TAG % "Emisor")\
        .find(XML_SCHEMA_TAG % "ExpedidoEn").get("calle")
    
    noExterior = node.find(XML_SCHEMA_TAG % "Emisor")\
           .find(XML_SCHEMA_TAG % "ExpedidoEn").get("noExterior")
    
    noInterior = node.find(XML_SCHEMA_TAG % "Emisor")\
           .find(XML_SCHEMA_TAG % "ExpedidoEn").get("noInterior")
    
    colonia = node.find(XML_SCHEMA_TAG % "Emisor")\
          .find(XML_SCHEMA_TAG % "ExpedidoEn").get("colonia")
    
    localidad = node.find(XML_SCHEMA_TAG % "Emisor")\
          .find(XML_SCHEMA_TAG % "ExpedidoEn").get("localidad") 
    
    referencia = "Sin Referencia" # @todo: Get real information
    
    municipio = node.find(XML_SCHEMA_TAG % "Emisor")\
          .find(XML_SCHEMA_TAG % "ExpedidoEn").get("municipio")
    
    estado = node.find(XML_SCHEMA_TAG % "Emisor")\
         .find(XML_SCHEMA_TAG % "ExpedidoEn").get("estado")
    
    pais = node.find(XML_SCHEMA_TAG % "Emisor")\
         .find(XML_SCHEMA_TAG % "ExpedidoEn").get("pais")
    
    codigoPostal = node.find(XML_SCHEMA_TAG % "Emisor")\
             .find(XML_SCHEMA_TAG % "ExpedidoEn").get("codigoPostal")
    
    
    """ 
    Tag: Receptor 
    Getting the attributes from de xml and setting the correct format for
    the original string 
    """
    rfc_receptor = node.find(XML_SCHEMA_TAG % "Receptor").get("rfc")
    nombre_receptor = node.find(XML_SCHEMA_TAG % "Receptor").get("nombre")
    
    """ 
    Tag: Domicilio Receptor
    Getting the attributes from de xml and setting the correct format for
    the original string 
    """
    calle_receptor = node.find(XML_SCHEMA_TAG % "Receptor")\
             .find(XML_SCHEMA_TAG % "Domicilio").get("calle")
    
    noExterior_receptor = node.find(XML_SCHEMA_TAG % "Receptor")\
                .find(XML_SCHEMA_TAG % "Domicilio").get("noExterior")
    
    noInterior_receptor = node.find(XML_SCHEMA_TAG % "Receptor")\
                .find(XML_SCHEMA_TAG % "Domicilio").get("noInterior")
    
    colonia_receptor = node.find(XML_SCHEMA_TAG % "Receptor")\
               .find(XML_SCHEMA_TAG % "Domicilio").get("colonia")
    
    localidad_receptor = node.find(XML_SCHEMA_TAG % "Receptor")\
               .find(XML_SCHEMA_TAG % "Domicilio").get("localidad")
    
    municipio_receptor = node.find(XML_SCHEMA_TAG % "Receptor")\
               .find(XML_SCHEMA_TAG % "Domicilio").get("municipio")
    
    estado_receptor = node.find(XML_SCHEMA_TAG % "Receptor")\
              .find(XML_SCHEMA_TAG % "Domicilio").get("estado")
    
    pais_receptor = node.find(XML_SCHEMA_TAG % "Receptor")\
            .find(XML_SCHEMA_TAG % "Domicilio").get("pais")
    
    codigoPostal_receptor  = node.find(XML_SCHEMA_TAG % "Receptor")\
                 .find(XML_SCHEMA_TAG % "Domicilio").get("codigoPostal")
    
    """ 
    Tag: Conceptos
    Getting the attributes from de xml and setting the correct format for
    the original string 
    """
    conceptos = node.find(XML_SCHEMA_TAG % "Conceptos").getchildren()
    concept_list = []
    for concepto in conceptos:
      concept_dict = {}
      for key in concepto.keys():         
        concept_dict["cantidad"] = int(concepto.get("cantidad"))
        concept_dict["descripcion"] = unicode(concepto.get("descripcion"))
        concept_dict["importe"] = float(concepto.get("importe"))
        concept_dict["importe"] = round(concept_dict["importe"],2)
        concept_dict["noIdentificacion"] = unicode(concepto.get("noIdentificacion"))
        concept_dict["valorUnitario"] = float(concepto.get("valorUnitario"))
        concept_dict["unidad"] = unicode(concepto.get("unidad"))
      concept_list.append(concept_dict)
         
    conceptos = concept_list
    
    """ 
    Tag: Impuestos
    Getting the attributes from de xml and setting the correct format for
    the original string 
    """
    impuestos_dict = {
      "retenciones" : {},
      "traslados" : {},
      "totalImpuestosRetenidos" : 0.0,
      "totalImpuestosTrasladados" : 0.0
      
    }
    impuestos = node.find(XML_SCHEMA_TAG % "Impuestos")
    
    for key in impuestos.keys():
      impuestos_dict[key] = impuestos.get(key)
    
    
    try:
      traslados =  impuestos.find(XML_SCHEMA_TAG % "Traslados")
      for element in traslados.getchildren():
        impuestos_dict["traslados"][element.get("impuesto")] = {}
        impuestos_dict["traslados"][element.get("impuesto")]\
                [round(float(element.get("tasa")),2)] = \
                round(float(element.get("importe")),2)
      impuestos = node.find(XML_SCHEMA_TAG % "Impuestos")
    except Exception, e:
      pass
    
    try:
      retenciones =  impuestos.find(XML_SCHEMA_TAG % "Retenciones")
      for element in retenciones.getchildren():
        impuestos_dict["retenciones"][element.get("impuesto")] = {}
        impuestos_dict["retenciones"][element.get("impuesto")]\
                [round(float(element.get("tasa")),2)] = \
                round(float(element.get("importe")),2)
    except Exception, e:
      pass
    
    try:
      complemento = self.root_invoice.find(XML_SCHEMA_TAG % "Complemento")
      timbre_fiscal = complemento.find(XML_SCHEMA_COMPLEMENT_TAG % 'TimbreFiscalDigital')
      timbre = {}
      for key in timbre_fiscal.keys():
        if key != '{http://www.w3.org/2001/XMLSchema-instance}schemaLocation':
          timbre[key] = timbre_fiscal.get(key)
    except Exception:
      pass
    
    
    
    response_dict = {
      "comprobante" : {
        "serie" : serial if serial else "",
        "folio" : folio if folio else "",
        "fecha" : fecha if fecha else "",
        #"noAprobacion" : invoice.approval_no,
        #"anoAprobacion" : invoice.approval_year,
        "tipoDeComprobante" : tipoDeComprobante if \
                    tipoDeComprobante else "", 
        "formaDePago" : formaDePago if formaDePago else "",
        "condicionesDePago" : condicionesDePago if condicionesDePago \
                    else "",# @todo: Get real information
        "subtotal" : subtotal if subtotal else "",
        "descuento" : descuento if descuento else "",
        "total" : total if total else "",
        "certificado" : certificado if certificado else "" 
      },
      "emisor" : {
         "rfc" : rfc if rfc else "",
         "nombre" : nombre if nombre else ""
      },
      "domicilioFiscal" : {
        "calle" : calle if calle else "",
        "noExterior" : noExterior if noExterior else "",
        "noInterior" : noInterior if noInterior else "",
        "colonia" : colonia if colonia else "",
        "localidad" : localidad if localidad else "", 
        "referencia" : "Sin Referencia",# @todo: Get real information
        "municipio" : municipio if municipio else "", 
        "estado" :  estado if estado else "", 
        "pais" :pais if pais else "", 
        "codigoPostal" : codigoPostal if codigoPostal else "", 
      },
       "expedidoEn" : {
        "calle" : calle if calle else "",
        "noExterior" : noExterior if noExterior else "",
        "noInterior" : noInterior if noInterior else "",
        "colonia" : colonia if colonia else "",
        "localidad" : localidad if localidad else "",
        "referencia" : "Sin Referencia",# @todo: Get real information
        "municipio" : municipio if municipio else "",
        "estado" : estado if estado else "",
        "pais" : pais if pais else "",
        "codigoPostal" : codigoPostal if codigoPostal else "" 
      },
       "receptor" : {
        "rfc" : rfc_receptor if rfc_receptor else "", 
        "nombre" : nombre_receptor if rfc_receptor else ""
      },
      "domicilio" : {
        "calle" : calle_receptor if calle_receptor else "",
        "noExterior" : noExterior_receptor if calle_receptor else "",
        "noInterior" : noInterior_receptor if noInterior_receptor else "",
        "colonia" : calle_receptor if calle_receptor else "",
        "localidad" : localidad_receptor if localidad_receptor else "",
        "referencia" : "Sin Referencia",# @todo: Get real information
        "municipio" : municipio_receptor if municipio_receptor else "",
        "estado" : estado_receptor if estado_receptor else "",#address_municipality,
        "pais" : pais_receptor if pais_receptor else "",
        "codigoPostal" : codigoPostal_receptor if codigoPostal_receptor else ""
      },
      "conceptos" : conceptos,
      "impuestos" : impuestos_dict,
      "timbre" : timbre
    }
    
    
    return response_dict
  
  
  def gen_original_string(self):
    xml_invoice_dict= self.get_dict_from_invoice_xml()
    original_string = render_to_string(
    'template/cadena.html',
    xml_invoice_dict)
    
    original_string = re.sub('\|\s+|\s+\|','|',original_string)
    original_string = re.sub('\s{2,}',' ',original_string)
    original_string = original_string.encode('utf-8')
    return original_string
  

class XMLValidator():
  """
  This class is responsible of validate a XML string vs an XMLSchema.
  
  @author: Alfredo Herrejon
  """
  
  def __init__(self, xml_etree=None):
    self.xml_string = self.remove_addenda(xml_etree)
    self.xsd_string =  self.get_xsd_string()
  
  
  def get_xsd_string(self):
    xsd_path = os.path.join(os.path.dirname(__file__),"")
    xsd_path = "%s/xsd/%s" % (xsd_path, XML_XSD_CFDI_VERSION)
    xsd_path_file = "%s/%s" % (xsd_path, XML_XSD_CDF_NAME)
    xsd_complements_path = "%s/complementos" % xsd_path
    xsd_file = open(xsd_path_file)
    xsd_string = "".join(xsd_file.readlines())
    xsd_string = xsd_string.replace('{{XSD_COMPLEMENTS_PATH}}', xsd_complements_path)
    return xsd_string

  def remove_addenda(self, xml_etree=None):     
    to_remove = None
    try:
      #to_remove = xml_etree.find(XML_INVOICE_NAMESPACE % "Complemento").find(XML_INVOICE_NAMESPACE % "Addenda")
      to_remove = xml_etree.find(XML_INVOICE_NAMESPACE % "Addenda")
    except:      
      pass
    if to_remove is not None:      
      #xml_etree.find(XML_INVOICE_NAMESPACE % "Complemento").remove(to_remove)    
      xml_etree.remove(to_remove)    
    self.addenda = to_remove
    invoice_utf = etree.tostring(xml_etree, encoding='UTF-8')
    return invoice_utf
      
  def is_valid(self):
    success = True
    message = "The XML invoice document is valid in the version XSD %s" % XML_XSD_CFDI_VERSION
    try:
      schema_root = etree.XML(self.xsd_string)
      schema = etree.XMLSchema(schema_root)
      parser = etree.XMLParser(schema = schema)
      root = etree.fromstring(self.xml_string, parser)
    except Exception as e:
      message = str(e)
      success = False
    data = {
      'addenda' : self.addenda,
      'success' : success,
      'message' : message
    }
    
    return data 

class AmountValidator():
  """
  This class is responsible of validate the amounts in the XML.
  
  @author: Alfredo Herrejon
  """
  
  def __init__(self, xml_etree=None):

    self.valid = True
    self.xml_etree = xml_etree
    self.subtotal = float(xml_etree.get('subTotal'))
    self.total = float(xml_etree.get('total'))
    try:
      self.totalImpuestosTrasladados = float(xml_etree.find(XML_INVOICE_NAMESPACE % 'Impuestos').get('totalImpuestosTrasladados'))
    except:
      self.totalImpuestosTrasladados = 0.0
    try:
      self.totalImpuestosRetenidos = float(xml_etree.find(XML_INVOICE_NAMESPACE % 'Impuestos').get('totalImpuestosRetenidos'))
    except:
      self.totalImpuestosRetenidos = 0.0

    self.check_concepts()
    if self.valid:
      print {'success': True, 'message': "Concepts amounts are correct"}
      if abs(self.subtotal-self.total_concepts) > 0.01:
        self.valid = False
        self.error = "Los Conceptos y el SubTotal no Concuerdan"
      else:
        self.check_taxes()
        if self.valid:
          print {'success': True, 'message': "Tax amounts are correct"}
          self.check_complements()

  def check_concepts(self):
    
    self.total_concepts = 0.0
    self.concepts_node = self.xml_etree.find(XML_INVOICE_NAMESPACE % 'Conceptos')
    self.concepts = self.concepts_node.getchildren()

    for concept in self.concepts:
      quantity = float(concept.get('cantidad'))
      unit_price = float(concept.get('valorUnitario'))
      amount = float(concept.get('importe'))
      total = quantity * unit_price
      if abs(amount-total) > 0.01:
        description = concept.get('descripcion')
        self.valid = False
        self.error = "Las cantidades en el concepto %s no concuerdan %s <> %s" % (description, str(total), str(amount))
        break
      else:
        self.total_concepts += amount

  def check_taxes(self):   
    #import pdb; pdb.set_trace() 
    try:
      self.taxes = self.xml_etree.find(XML_INVOICE_NAMESPACE % "Impuestos")
      try:
        self.transferred = self.taxes.find(XML_INVOICE_NAMESPACE % "Traslados").getchildren()
      except:
        self.transferred = []
      try:
        self.retained = self.taxes.find(XML_INVOICE_NAMESPACE % "Retenciones").getchildren()
      except:
        self.retained = []
    except:
      pass

    self.total_transferred = 0.0
    for transferred in self.transferred:
      amount = float(transferred.get('importe'))
      #rate = float(transferred.get('tasa'))      
      #total = self.subtotal * rate / 100
      if False and abs(amount-total) > 0.01:
        description = transferred.get('impuesto')
        self.valid = False
        self.error = "Las cantidades en los Impuestos de Traslado %s no concuerdan %s <> %s" % (description, str(total), str(amount))
        break
      else:
        self.total_transferred += amount

    if self.valid and self.totalImpuestosTrasladados > 0 and abs(self.total_transferred-self.totalImpuestosTrasladados) > 0.01:
      self.valid = False
      self.error = "Las Cantidades de los Impuestos Trasladados no concuerdan %s <> %s" %(self.total_transferred,self.totalImpuestosTrasladados)

    self.total_retained = 0.0
    for retained in self.retained:      
      amount = float(retained.get('importe'))
      #rate = retained.get('tasa')
      #total = self.subtotal * rate / 100
      if False and abs(amount-total) > 0.01:
        description = transferred.get('impuesto')
        self.valid = False
        self.error = "Las cantidades en los Impuestos de Retencion %s no concuerdan %s <> %s" % (description, str(total), str(amount))
        break
      else:
        self.total_retained += amount

    if self.valid and self.totalImpuestosRetenidos > 0 and abs(self.total_retained-self.totalImpuestosRetenidos) > 0.01:
      self.valid = False
      self.error = "Las Cantidades de los Impuestos Retenidos no concuerdan %s <> %s" %(self.total_retained,self.totalImpuestosRetenidos)

  def check_complements(self):
    #import pdb; pdb.set_trace()
    self.complement_retained_tax = 0.0
    self.complement_transferred_tax = 0.0
    self.complement_node = None
    try:
      self.complement_node = self.xml_etree.find(XML_INVOICE_NAMESPACE % "Complemento")
    except:
      pass
    if self.valid and self.complement_node is not None:
      #self.complement_node.find("{http://www.sat.gob.mx/detallista}detallista"):
      #self.complement_node.find("{http://www.sat.gob.mx/divisas}Divisas"):
      #self.complement_node.find("{http://www.sat.gob.mx/iedu}instEducativas"):
      #self.complement_node.find("{http://www.sat.gob.mx/donat}Donatarias"):
      #self.complement_node.find("{http://www.sat.gob.mx/pfic}PFintegranteCoordinado"):
      #self.complement_node.find("{http://www.sat.gob.mx/leyendasFiscales}LeyendasFiscales"):
      #self.complement_node.find("{http://www.sat.gob.mx/ventavehiculos}VentaVehiculos"):
      #self.complement_node.find("{http://www.sat.gob.mx/TuristaPasajeroExtranjero}TuristaPasajeroExtranjero"):
      #self.complement_node.find("{http://www.sat.gob.mx/spei}Complemento_SPEI"):
      #self.xml_etree.find("{http://www.sat.gob.mx/terceros}PorCuentadeTerceros"):
      self.complement_ecc = self.complement_node.find("{http://www.sat.gob.mx/ecc}EstadoDeCuentaCombustible")
      if self.valid and self.complement_ecc is not None:
        self.complement_ecc_concepts = self.complement_ecc.find("{http://www.sat.gob.mx/ecc}Conceptos")
        self.total_complement_concepts = 0.0
        for concept in self.complement_ecc_concepts:
          quantity = float(concept.get('cantidad'))
          unit_price = float(concept.get('valorUnitario'))
          amount = float(concept.get('importe'))
          total = quantity * unit_price
          if abs(amount-total) > 0.01:
            description = concept.get('nombreCombustible')
            self.valid = False
            self.error = "Las cantidades en el ConceptoEstadoDeCuentaCombustible %s no concuerdan %s<>%s" % (description, str(total), str(amount))
            break
          else:
            self.total_complement_concepts += amount
            self.complement_ecc_concept_transferred = concept.find("{http://www.sat.gob.mx/ecc}Traslados")
            for transferred in self.complement_ecc_concept_transferred:
              rate = float(transferred.get('tasa'))
              transferred_amount = float(transferred.get('importe'))
              transferred_total = amount * rate / 100
              if abs(transferred_total-transferred_amount) > 0.01:
                self.valid = False
                self.error = "Las cantidades en el Traslado del ConceptoEstadoDeCuentaCombustible %s no concuerdan importe=%s tasa%s importe%s" % (description, amount, rate, transferred_amount)
                break
      self.complement_ecb = self.complement_node.find("{http://www.sat.gob.mx/ecb}EstadoDeCuentaBancario")
      if self.valid and self.complement_ecb is not None:
        self.complement_ecb_mvecb = self.complement_node.find("{http://www.sat.gob.mx/ecb}MovimientoECB")
        self.complement_ecb_mvecbf = self.complement_node.find("{http://www.sat.gob.mx/ecb}MovimientoECBFiscal")
        total_mvecb = 0.0
        for mvecb in self.complement_ecb_mvecb:
          total_mvecb += float(mvecb.get('importe'))
        if abs(self.subtotal-total_mvecb) > 0.01:
          self.valid = False
          self.error = "Las cantidades en EstadoDeCuentaBancario en los nodos MovimientoECB no concuerdan %s <> %s" % (self.subtotal, total_mvecb)
        total_mvecbf = 0.0
        for mvecbf in self.complement_ecb_mvecbf:
          total_mvecbf += float(mvecbf.get('Importe'))
        if abs(self.subtotal-total_mvecbf) > 0.01:
          self.valid = False
          self.error = "Las cantidades en EstadoDeCuentaBancario en los nodos MovimientoECBFiscal no concuerdan %s <> %s" % (self.subtotal, total_mvecbf)
        if abs(total_mvecb-total_mvecbf) > 0.01:
          self.valid = False
          self.error = "Las cantidades en los nodos MovimientoECB y MovimientoECBFiscal no concuerdan %s <> %s" % (total_mvecb, total_mvecbf)

      #import pdb; pdb.set_trace()
      self.complement_imploc = self.complement_node.find("{http://www.sat.gob.mx/implocal}ImpuestosLocales")
      if self.valid and self.complement_imploc is not None:
        self.complement_total_retained = float(self.complement_imploc.get('TotaldeRetenciones'))
        self.complement_total_transferred = float(self.complement_imploc.get('TotaldeTraslados'))
        self.complement_imploc_retained = self.complement_imploc.findall("{http://www.sat.gob.mx/implocal}RetencionesLocales")
        self.complement_imploc_transferred = self.complement_imploc.findall("{http://www.sat.gob.mx/implocal}TrasladosLocales")
        total_imploc_retained = 0.0
        total_imploc_transferred = 0.0
        for retained in self.complement_imploc_retained:
          rate = float(retained.get('TasadeRetencion'))
          amount = float(retained.get('Importe'))
          total_amount = self.subtotal * rate / 100
          if abs(total_amount-amount) > 0.01:
            description = retained.get('ImpLocRetenido')
            self.valid = False
            self.error = "Las cantidades en las RetencionesLocales %s no concuerdan %s <> %s" % (description, total_amount, amount)
            break
          else:
            total_imploc_retained += amount
        for transferred in self.complement_imploc_transferred:
          rate = float(transferred.get('TasadeTraslado'))
          amount = float(transferred.get('Importe'))
          total_amount = self.subtotal * rate / 100
          if abs(total_amount-amount) > 0.01:
            description = transferred.get('ImpLocTrasladado')
            self.valid = False
            self.error = "Las cantidades en los TrasladosLocales %s no concuerdan %s <> %s" % (description, total_amount, amount)
            break
          else:
            total_imploc_transferred += amount
        new_total = self.subtotal + self.totalImpuestosTrasladados - self.totalImpuestosRetenidos + total_imploc_transferred - total_imploc_retained
        if self.valid and abs(new_total-self.total) > 0.01:
          self.valid = False
          self.error = "Las cantidades no concuerdan: subTotal + totalImpuestosTrasladados - totalImpuestosRetenidos + TotaldeTraslados - TotaldeRetenciones = total : %s + %s - %s + %s - %s = %s" % (self.subtotal, self.totalImpuestosTrasladados, self.totalImpuestosRetenidos, total_imploc_transferred, total_imploc_retained, self.total)

        
  def is_valid(self):
    success = True
    message = "The Content in the XML invoice is valid, all the Amounts and Taxes are OK"
    if not self.valid:
      success = False
      message = self.error

    data = {
      'success' : success,
      'message' : message
    }
    
    return data 
    


