# - *- coding: utf- 8 - *- .
# SNEAKS - Snooping Early Alert Knowledge Service

from ConfigParser import RawConfigParser
from datetime import datetime, timedelta
import codecs
import logging
import urlparse
import ftplib
import re
import apache_log_parser
from referer_parser import Referer
from unidecode import unidecode
from operator import itemgetter


class DataSource:

    def __read_config(self):
        """
        Obtiene la configuración de la persona de su archivo .person y devuelve True si es válida
        """
        parser = RawConfigParser()
        with codecs.open("config/" + self.person + '.person', 'r', encoding='utf-8') as f:
            parser.readfp(f)
        if parser.has_section("web_bug"):
            if parser.has_option("web_bug", 'search_terms'):
                self.__search_terms = parser.get("web_bug", 'search_terms')
                if self.__search_terms == '':
                    return False
            else:
                return False
            if parser.has_option("web_bug", 'weight'):
                self.__weight = parser.getint("web_bug", 'weight')
            if parser.has_option("web_bug", 'weight_no_search_terms'):
                self.__weight_no_search_terms = parser.getint("web_bug", 'weight_no_search_terms')
            if parser.has_option("web_bug", 'weight_visit'):
                self.__weight_visit = parser.getint("web_bug", 'weight_visit')
            if parser.has_option("web_bug", 'webbug_log'):
                self.__webbug_log =\
                    [e.strip() for e in parser.get("web_bug", 'webbug_log').split(',')]
                if self.__webbug_log == ['']:
                    return False
            else:
                return False
        else:
            return False
        return True

    def __init__(self, person):
        self.__logger = logging.getLogger('sneaks.web_bug')
        self.person = person
        self.__search_terms = ''
        self.__weight = 5
        self.__weight_no_search_terms = 2
        self.__weight_visit = 0
        self.__webbug_log = []
        self.enabled = self.__read_config()
        self.fetched_data = []
        self.__eval_expression = self.__build_eval_expression()
        self.__webbug_log_format = "%h %t \"%r\" \"%{Referer}i\" \"%{User-agent}i\""

        if self.enabled:
            self.__logger.info('Activado para %s', self.person)
        else:
            self.__logger.error('Error leyendo la configuración de %s', self.person)

    def get_data(self, already_downloaded_sources):
        """
        Descarga los archivos webbug.log y almacena las detecciones en el archivo wb-[servidor]-[nombreusuario]-events.log
        """
        self.fetched_data = []
        if not self.enabled:
            return False

        for ftpsite in self.__webbug_log:

            addr = urlparse.urlparse(ftpsite)

            url_downloaded = [downloaded[0] for downloaded in already_downloaded_sources]
            sremoteaddr = addr.scheme + "://" + addr.hostname + addr.path
            if url_downloaded.count(sremoteaddr):  # Si el fichero ya ha sido descargado por otro plugin, se copia
                already_downloaded_file = already_downloaded_sources[url_downloaded.index(sremoteaddr)]
                self.fetched_data.append(already_downloaded_file)
                self.__logger.info('Reusado %s de %s descargado recientemente', addr.path, addr.hostname)

            else:  # Si no es así, se descarga
                filename = "temp/wb-" + addr.hostname + '-' + self.person + "-access.log"
                localfile = open(filename, 'wb')
                try:
                    connftp = ftplib.FTP(addr.hostname)
                    connftp.login(addr.username, addr.password)
                    connftp.retrbinary('RETR ' + addr.path, localfile.write)
                    self.fetched_data.append([addr.scheme + "://" + addr.hostname + addr.path, filename])
                    self.__logger.info('Descargado webbug.log de %s', addr.hostname)

                    void_file = open("temp/void_file", 'wb')
                    void_file.close()
                    void_file = open("temp/void_file", "rb")
                    connftp.storbinary("STOR " + addr.path, void_file)  # Vaciamos el webbug.log
                    void_file.close()

                    connftp.quit()
                    localfile.close()
                except:
                    self.__logger.error('Error conectando al servidor [%s] de %s', addr.hostname, self.person)

                localfile.close()

        line_parser = apache_log_parser.make_parser(self.__webbug_log_format.decode('string_escape'))
        for fdownloaded in self.fetched_data:
            
            ftemp_accesslog = open(fdownloaded[1], 'r')
            addr = urlparse.urlparse(fdownloaded[0])
            fevents_filename = "data/wb-" + addr.hostname + '-' + self.person + "-events.log"

            try:  # lee la fecha y hora de la última linea, si es que existe el archivo
                with open(fevents_filename, "rb") as sf:
                    sfirstline = sf.readline()
                    sf.seek(-2, 2)
                    try:
                        while sf.read(1) != "\n":
                            sf.seek(-2, 1)
                        slastline = sf.readline()
                    except IOError:
                        slastline = sfirstline
                last_event_logged = line_parser(slastline)
                last_event_logged_time = last_event_logged['time_received_datetimeobj']
            except IOError:
                last_event_logged_time = datetime(1, 1, 1, 1, 1, 1)

            fevents = open(fevents_filename, 'a')

            while True:
                linea = ftemp_accesslog.readline()
                if not linea:
                    break
                log_line_data = line_parser(linea)
                referer_url = log_line_data['request_header_referer']
                web_bug_location = log_line_data['request_first_line']
                ref = Referer(referer_url)

                if (last_event_logged_time < log_line_data['time_received_datetimeobj']) and (web_bug_location != "-")\
                        and ((self.__weight_visit > 0) or (ref.medium == 'search')):

                    if ref.search_term is not None:
                        ref_list = unidecode(ref.search_term.decode('utf-8')).replace("\"", "").split()
                        if eval(self.__eval_expression):
                            fevents.write(linea)
                    else:
                        fevents.write(linea)

            ftemp_accesslog.close()
            fevents.close()
        if self.fetched_data:
            return True

    def __build_eval_expression(self):
        """
        Convierte la expresión booleana de terminos de búsqueda en una expresión evaluable y segura.
        Esto incluye modificar los términos para pasar a minúsculas, eliminar diacríticos y solo permitir a-z
        """
        expression = ""
        i = 0
        while i < len(self.__search_terms):
            if self.__search_terms[i] == ' ':
                i += 1
            elif self.__search_terms[i] == '(':
                expression += '('
                i += 1
            elif self.__search_terms[i] == ')':
                expression += ')'
                i += 1
            elif self.__search_terms[i:(i+3)] == 'and':
                expression += ' and '
                i += 3
            elif self.__search_terms[i:(i+2)] == 'or':
                expression += ' or '
                i += 2
            elif self.__search_terms[i:(i+3)] == 'not':
                expression += ' not '
                i += 3
            else:
                f = -1
                for s in self.__search_terms[i:]:
                    if (s == ' ') | (s == '(') | (s == ')'):
                        f = self.__search_terms[i:].find(s)
                        break
                if f != -1:
                    term = re.sub(r'[^a-z]', '', unidecode(self.__search_terms[i:i+f].lower()))
                    expression += "(\"" + term + "\" in ref_list)"
                    i += f
                else:
                    term = re.sub(r'[^a-z]', '', unidecode(self.__search_terms[i:].lower()))
                    expression += "(\"" + term + "\" in ref_list)"
                    break
        return expression

    def eval_data(self, time_frame, analyzed_time, given_time, confirmed_ips):
        """
        Devuelve una lista con un elemento por cada uno de los últimos 'check_interval' minutos antes de la hora
        'given_time'. Cada elemento de la lista devuelta contiene el valor acumulado de las detecciones durante
        los 'time_frame' minutos anteriores.
        """
        eval_time = time_frame + analyzed_time
        detect_list = [0] * eval_time
        acum_list = [0] * analyzed_time
        if not self.enabled:
            return acum_list

        time_now_utc = datetime(given_time.year, given_time.month, given_time.day, given_time.hour, given_time.minute)

        line_parser = apache_log_parser.make_parser(self.__webbug_log_format.decode('string_escape'))
        for remoteaddr in self.__webbug_log:

            addr = urlparse.urlparse(remoteaddr)  # Se obtiene el nombre del fichero de eventos
            filename = "data/wb-" + addr.hostname + '-' + self.person + "-events.log"

            with open(filename, 'r') as f:

                linea = f.readline()  # Detección de zona horaria en la primera linea del log
                if linea:
                    p = re.compile(r"[\+|-]\d\d\d\d\]")
                    tz = p.findall(linea)[0]
                    timezone = timedelta(hours=int(tz[0:3]), minutes=int(tz[0]+tz[3:5]))

                visiting_ips = []
                while linea:
                    log_line_data = line_parser(linea)
                    current_ip = log_line_data['remote_host']
                    if confirmed_ips.count(current_ip):

                        l = log_line_data['time_received_datetimeobj']
                        line_time_utc = datetime(l.year, l.month, l.day, l.hour, l.minute) - timezone

                        if line_time_utc > time_now_utc:
                            break

                        i = int((time_now_utc - line_time_utc).total_seconds()/60)  # Conversión hora a índice
                        if i < eval_time:
                            ref = Referer(log_line_data['request_header_referer'])
                            origin = urlparse.urlparse(log_line_data['request_first_line'])
                            if (ref.medium == 'search') and (ref.search_term is not None):  # Una búsqueda con términos
                                detect_list[eval_time - i - 1] += self.__weight
                            elif (ref.medium == 'search') and (ref.search_term is None):  # Una búsqueda sin términos
                                detect_list[eval_time - i - 1] += self.__weight_no_search_terms
                            elif (self.__weight_visit > 0) and \
                                    (not visiting_ips.count([current_ip, origin.hostname])):  # Una simple visita
                                visiting_ips.append([current_ip, origin.hostname])  # Solo puntuan una vez por ip/origen
                                detect_list[eval_time - i - 1] += self.__weight_visit

                    linea = f.readline()

                for i in range(1, analyzed_time + 1):  # Acumulacción de pesos de detección para los rangos dados
                    #print "acumulado", analyzed_time - i, "= suma desde",  eval_time - time_frame - i, "hasta", eval_time - i, "=", detect_list[eval_time - time_frame - i:eval_time - i + 1], "=", sum(detect_list[eval_time - time_frame - i:eval_time - i])
                    acum_list[analyzed_time - i] = sum(detect_list[eval_time - time_frame - i:eval_time - i + 1])

        return acum_list

    def get_report_data(self, time_frame, given_time, confirmed_ips):
        """
        Devuelve una lista con cada una de las detecciones durante los 'time_frame' minutos previos a
        la hora 'given_time'. Cada elemento contiene la hora de la detección, el sitio donde se detectó,
        la ip del footprinter, la puntuación y un texto descriptivo sobre la misma.
        """
        report_list = []
        if not self.enabled:
            return report_list
        delta_frame = timedelta(minutes=time_frame)

        line_parser = apache_log_parser.make_parser(self.__webbug_log_format.decode('string_escape'))
        for remoteaddr in self.__webbug_log:

            addr = urlparse.urlparse(remoteaddr)  # Se obtiene el nombre del fichero de eventos
            filename = "data/wb-" + addr.hostname + '-' + self.person + "-events.log"

            with open(filename, 'r') as f:

                linea = f.readline()  # Detección de zona horaria en la primera linea del log
                if linea:
                    p = re.compile(r"[\+|-]\d\d\d\d\]")
                    tz = p.findall(linea)[0]
                    timezone = timedelta(hours=int(tz[0:3]), minutes=int(tz[0]+tz[3:5]))

                simple_visits = []
                while True:
                    if not linea:
                        break

                    log_line_data = line_parser(linea)
                    ip = log_line_data['remote_host']

                    if confirmed_ips.count(ip):

                        line_time_utc = log_line_data['time_received_datetimeobj'] - timezone

                        if line_time_utc > given_time:
                            break
                        if line_time_utc > given_time - delta_frame:
                            origin = log_line_data['request_first_line']
                            ref = Referer(log_line_data['request_header_referer'])
                            origin_hostname = urlparse.urlparse(origin).hostname
                            if (ref.medium == 'search') and (ref.search_term is not None):  # Una búsqueda con términos
                                sterms = ref.search_term.decode('utf-8')
                                sengine = ref.referer.decode('utf-8')
                                description = u'Una busqueda desde [' + sengine + u'] con los terminos: [' + sterms +\
                                              u'] ha llegado a [' + origin + ']'
                                report_list.append([line_time_utc, log_line_data['remote_host'], description, 'Web Bug'])

                            elif (ref.medium == 'search') and (ref.search_term is None):  # Una búsqueda sin términos
                                sengine = ref.referer.decode('utf-8')
                                description = u'Una busqueda desde [' + sengine + u'] ha llegado a [' + origin + ']'
                                report_list.append([line_time_utc, log_line_data['remote_host'], description, 'Web Bug'])

                            elif (self.__weight_visit > 0) and (not simple_visits.count([ip, origin_hostname])):
                                simple_visits.append([ip, origin_hostname])  # Una simple visita
                                description = u'Una visita ha llegado a [' + origin + ']'
                                report_list.append([line_time_utc, log_line_data['remote_host'], description, 'Web Bug'])

                    linea = f.readline()

        if report_list:
            return sorted(report_list, key=itemgetter(0))
        else:
            return report_list

    def get_ips(self, time_frame, given_time):
        """
        Devuelve una lista con cada una de las IP's detectadas durante los 'time_frame' minutos previos a la hora
        'given_time'. Acompañando a cara IP irá una marca de verificación (True/False), que indicará si la detección
        de esa IP es concluyente o es necesaria la confirmación del positivo por parte de otro plugin.
        """
        ip_list = []
        if not self.enabled:
            return ip_list
        delta_frame = timedelta(minutes=time_frame)

        line_parser = apache_log_parser.make_parser(self.__webbug_log_format.decode('string_escape'))
        for remoteaddr in self.__webbug_log:

            addr = urlparse.urlparse(remoteaddr)  # Se obtiene el nombre del fichero de eventos
            filename = "data/wb-" + addr.hostname + '-' + self.person + "-events.log"

            with open(filename, 'r') as f:

                linea = f.readline()  # Detección de zona horaria en la primera linea del log
                if linea:
                    p = re.compile(r"[\+|-]\d\d\d\d\]")
                    tz = p.findall(linea)[0]
                    timezone = timedelta(hours=int(tz[0:3]), minutes=int(tz[0]+tz[3:5]))

                while True:
                    if not linea:
                        break
                    log_line_data = line_parser(linea)
                    line_time_utc = log_line_data['time_received_datetimeobj'] - timezone

                    if line_time_utc > given_time:
                        break

                    if line_time_utc > given_time - delta_frame:
                        ip = log_line_data['remote_host']
                        ip_only_list = [a[0] for a in ip_list]
                        origin = urlparse.urlparse(log_line_data['request_first_line']).hostname
                        ref = Referer(log_line_data['request_header_referer'])
                        if not ip_only_list.count(ip):
                            if (ref.medium == 'search') and (ref.search_term is not None):
                                ip_list.append([ip, True, origin])  # IP nueva, la añadimos
                            else:
                                ip_list.append([ip, False, origin])
                        elif origin != ip_list[ip_only_list.index(ip)][2]:
                            ip_list[ip_only_list.index(ip)][1] = True  # IP repetida en página distinta, es un positivo

                    linea = f.readline()

        return [c[0:2] for c in ip_list]