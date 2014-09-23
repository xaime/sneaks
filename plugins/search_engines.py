# - *- coding: utf- 8 - *- .
# SNEAKS - Snooping Early Alert Knowledge Service

from ConfigParser import RawConfigParser
from datetime import datetime, timedelta
import codecs
import logging
import urlparse
import urllib
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
        if parser.has_section("search_engines"):
            if parser.has_option('search_engines', 'search_terms'):
                self.__search_terms = parser.get('search_engines', 'search_terms')
                if self.__search_terms == '':
                    return False
            else:
                return False
            if parser.has_option('search_engines', 'weight'):
                self.__weight = parser.getint('search_engines', 'weight')
            if parser.has_option('search_engines', 'access_log'):
                self.__access_log =\
                    [e.strip() for e in parser.get('search_engines', 'access_log').split(',')]
                if self.__access_log == ['']:
                    return False
            else:
                return False
            if parser.has_option('search_engines', 'access_log_format'):
                self.__access_log_format =\
                    [e.strip() for e in parser.get('search_engines', 'access_log_format').split(',')]
                if self.__access_log_format == ['']:
                    return False
            else:
                return False
        else:
            return False
        return True

    def __init__(self, person):
        self.__logger = logging.getLogger('sneaks.search_engines')
        self.person = person
        self.__search_terms = ''
        self.__weight = 5
        self.__access_log = []
        self.__access_log_format = []
        self.enabled = self.__read_config()
        self.fetched_data = []
        self.__eval_expression = self.__build_eval_expression()

        if self.enabled:
            self.__logger.info('Activado para %s', self.person)
        else:
            self.__logger.error('Error leyendo la configuración de %s', self.person)

    def get_data(self, already_downloaded_sources):
        """
        Descarga los archivos access.log y almacena las detecciones en el archivo st-[servidor]-[nombreusuario]-events.log
        """
        self.fetched_data = []
        if not self.enabled:
            return False

        for remoteaddr in self.__access_log:

            addr = urlparse.urlparse(remoteaddr)

            url_downloaded = [downloaded[0] for downloaded in already_downloaded_sources]
            sremoteaddr = addr.scheme + "://" + addr.hostname + addr.path
            if url_downloaded.count(sremoteaddr):  # Si el fichero ya ha sido descargado por otro plugin, se copia
                already_downloaded_file = already_downloaded_sources[url_downloaded.index(sremoteaddr)]
                self.fetched_data.append(already_downloaded_file)
                self.__logger.info('Reusado %s de %s descargado recientemente', addr.path, addr.hostname)

            else:  # Si no es así, se descarga
                filename = "temp/st-" + addr.hostname + '-' + self.person + "-access.log"
                localfile = open(filename, 'wb')
                try:
                    remotefile = urllib.urlopen(remoteaddr)
                    localfile.write(remotefile.read())
                    remotefile.close()
                    self.fetched_data.append([addr.scheme + "://" + addr.hostname + addr.path, filename])
                    self.__logger.info('Descargado %s de %s', addr.path, addr.hostname)
                except:
                    self.__logger.error('Error obteniendo %s de %s', addr.path, addr.hostname)

                localfile.close()

        for fdownloaded in self.fetched_data:
            line_parser = apache_log_parser.make_parser\
                (self.__access_log_format[self.fetched_data.index(fdownloaded)].decode('string_escape'))
            ftemp_accesslog = open(fdownloaded[1], 'r')
            addr = urlparse.urlparse(fdownloaded[0])
            fevents_filename = "data/st-" + addr.hostname + '-' + self.person + "-events.log"

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
                if (last_event_logged_time < log_line_data['time_received_datetimeobj']) and \
                        (referer_url != "-") and (referer_url != ""):
                    ref = Referer(referer_url)
                    if ref.search_term is not None:
                        ref_list = unidecode(ref.search_term.decode('utf-8')).replace("\"", "").split()
                        if eval(self.__eval_expression):
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

        for remoteaddr in self.__access_log:

            addr = urlparse.urlparse(remoteaddr)  # Se obtiene el nombre del fichero de eventos
            filename = "data/st-" + addr.hostname + '-' + self.person + "-events.log"
            line_parser = apache_log_parser.make_parser\
                (self.__access_log_format[self.__access_log.index(remoteaddr)].decode('string_escape'))

            with open(filename, 'r') as f:

                linea = f.readline()  # Detección de zona horaria en la primera linea del log
                if linea:
                    p = re.compile(r"[\+|-]\d\d\d\d\]")
                    tz = p.findall(linea)[0]
                    timezone = timedelta(hours=int(tz[0:3]), minutes=int(tz[0]+tz[3:5]))

                while linea:
                    log_line_data = line_parser(linea)
                    if confirmed_ips.count(log_line_data['remote_host']):

                        l = log_line_data['time_received_datetimeobj']
                        line_time_utc = datetime(l.year, l.month, l.day, l.hour, l.minute) - timezone

                        if line_time_utc > time_now_utc:
                            break

                        i = int((time_now_utc - line_time_utc).total_seconds()/60)  # Conversión hora a índice de la lista
                        if i < eval_time:
                            detect_list[eval_time - i - 1] += self.__weight  # Lista de pesos de detección

                    linea = f.readline()
                #print "Detect list:", detect_list
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

        for remoteaddr in self.__access_log:

            addr = urlparse.urlparse(remoteaddr)  # Se obtiene el nombre del fichero de eventos
            filename = "data/st-" + addr.hostname + '-' + self.person + "-events.log"
            line_parser = apache_log_parser.make_parser\
                (self.__access_log_format[self.__access_log.index(remoteaddr)].decode('string_escape'))

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

                    if confirmed_ips.count(log_line_data['remote_host']):

                        line_time_utc = log_line_data['time_received_datetimeobj'] - timezone

                        if line_time_utc > given_time:
                            break
                        if line_time_utc > given_time - delta_frame:
                            ref = Referer(log_line_data['request_header_referer'])
                            sterms = ref.search_term.decode('utf-8')
                            sengine = ref.referer.decode('utf-8')
                            description = u'Una busqueda desde [' + sengine + u'] con los terminos: [' + sterms + \
                                          u'] ha llegado a [' + addr.hostname + ']'

                            report_list.append([line_time_utc, log_line_data['remote_host'],
                                                description, 'Search Engines'])

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

        for remoteaddr in self.__access_log:

            addr = urlparse.urlparse(remoteaddr)  # Se obtiene el nombre del fichero de eventos
            filename = "data/st-" + addr.hostname + '-' + self.person + "-events.log"
            line_parser = apache_log_parser.make_parser\
                (self.__access_log_format[self.__access_log.index(remoteaddr)].decode('string_escape'))

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
                        if not ip_list.count([ip, True]):
                            ip_list.append([ip, True])

                    linea = f.readline()

        return ip_list


#        for ftpsite in self.access_log:
#            urlftp = urlparse(ftpsite)
#            try:
#                connftp = ftplib.FTP(urlftp.hostname)
#                connftp.login(urlftp.username,urlftp.password)
#                localfile = open("data/" + urlftp.hostname + ".log", 'wb')
#                connftp.retrbinary('RETR ' + urlftp.path, localfile.write)
#                self.logger.info('Descargado access.log de %s', urlftp.hostname)
#               connftp.quit()
#                localfile.close()
#            except:
#                self.logger.error('Error conectando al servidor [%s] de %s', urlftp.hostname, self.person)
