# - *- coding: utf- 8 - *- .
# SNEAKS - Snooping Early Alert Knowledge Service

__author__ = 'Xaime'

from ConfigParser import RawConfigParser
from datetime import datetime, timedelta
import codecs
import logging
import urlparse
import urllib
import re
import apache_log_parser
from operator import itemgetter


class DataSource:

    def __read_config(self):
        """
        Obtiene la configuración de la persona de su archivo .person y devuelve True si es válida
        """
        parser = RawConfigParser()
        with codecs.open("config/" + self.person + '.person', 'r', encoding='utf-8') as f:
            parser.readfp(f)
        if parser.has_section("metadata_crawling"):
            if parser.has_option('metadata_crawling', 'files'):
                self.__files =\
                    [e.strip() for e in parser.get('metadata_crawling', 'files').split(',')]
                if self.__files == ['']:
                    return False
            else:
                return False
            if parser.has_option('metadata_crawling', 'weight'):
                self.__weight = parser.getint('metadata_crawling', 'weight')
            if parser.has_option('metadata_crawling', 'access_log'):
                self.__access_log = parser.get('metadata_crawling', 'access_log')
                if not self.__access_log:
                    return False
            else:
                return False
            if parser.has_option('metadata_crawling', 'access_log_format'):
                self.__access_log_format = parser.get('metadata_crawling', 'access_log_format')
                if not self.__access_log_format:
                    return False
            else:
                return False
        else:
            return False
        return True

    def __init__(self, person):
        self.__logger = logging.getLogger('sneaks.metadata_crawling')
        self.person = person
        self.__weight = 2
        self.__files = []
        self.__access_log = ''
        self.__access_log_format = ''
        self.enabled = self.__read_config()
        self.fetched_data = []

        if self.enabled:
            self.__logger.info('Activado para %s', self.person)
        else:
            self.__logger.error('Error leyendo la configuración de %s', self.person)

    def get_data(self, already_downloaded_sources):
        """
        Descarga los archivos access.log y almacena las detecciones en el archivo [servidor]-[nombreusuario]-events.log
        """
        self.fetched_data = []
        if not self.enabled:
            return False

        addr = urlparse.urlparse(self.__access_log)

        url_downloaded = [downloaded[0] for downloaded in already_downloaded_sources]
        sremoteaddr = addr.scheme + "://" + addr.hostname + addr.path
        if url_downloaded.count(sremoteaddr):  # Si el fichero ya ha sido descargado por otro plugin, se copia
            already_downloaded_file = already_downloaded_sources[url_downloaded.index(sremoteaddr)]
            self.fetched_data.append(already_downloaded_file)
            self.__logger.info('Reusado %s de %s descargado recientemente', addr.path, addr.hostname)

        else:  # Si no es así, se descarga
            filename = "temp/mc-" + addr.hostname + '-' + self.person + "-access.log"
            localfile = open(filename, 'wb')
            try:
                remotefile = urllib.urlopen(self.__access_log)
                localfile.write(remotefile.read())
                remotefile.close()
                self.fetched_data.append([addr.scheme + "://" + addr.hostname + addr.path, filename])
                self.__logger.info('Descargado %s de %s', addr.path, addr.hostname)
            except:
                self.__logger.error('Error obteniendo %s de %s', addr.path, addr.hostname)

            localfile.close()

        if self.fetched_data:
            ftemp_accesslog = open(self.fetched_data[0][1], 'r')
            addr = urlparse.urlparse(self.fetched_data[0][0])
            fevents_filename = "data/mc-" + addr.hostname + '-' + self.person + "-events.log"
            line_parser = apache_log_parser.make_parser(self.__access_log_format.decode('string_escape'))

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

            downloaded = []
            metadata_files = set()
            for metadata_url in self.__files:
                metadata_files.add(urlparse.urlparse(metadata_url).path)

            while True:
                linea = ftemp_accesslog.readline()
                if not linea:
                    break
                log_line_data = line_parser(linea)
                if last_event_logged_time < log_line_data['time_received_datetimeobj']:

                    if log_line_data['request_url'] in metadata_files:
                        downloaded.append([log_line_data['request_url'], log_line_data['remote_host'], linea])

            for ip in set([a[1] for a in downloaded]):  # Cada una de las distintas ips que han descargado los ficheros
                m = [b[0] for b in downloaded if b[1] == ip]
                if set(m) == metadata_files:  # Si los descargados son todos los vigilados se guarda el evento
                    for dlinea in downloaded:
                        if (dlinea[1] == ip) and (dlinea[0] in metadata_files):
                            fevents.write(dlinea[2])
                            break

            ftemp_accesslog.close()
            fevents.close()

            return True

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

        addr = urlparse.urlparse(self.__access_log)  # Se obtiene el nombre del fichero de eventos
        filename = "data/mc-" + addr.hostname + '-' + self.person + "-events.log"
        line_parser = apache_log_parser.make_parser(self.__access_log_format.decode('string_escape'))

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

        addr = urlparse.urlparse(self.__access_log)  # Se obtiene el nombre del fichero de eventos
        filename = "data/mc-" + addr.hostname + '-' + self.person + "-events.log"
        line_parser = apache_log_parser.make_parser\
            (self.__access_log_format.decode('string_escape'))

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
                        description = u'El conjunto de ficheros con metadatos ha sido descargado de  [' + \
                                      urlparse.urlparse(self.__files[0]).hostname + ']'

                        report_list.append([line_time_utc, log_line_data['remote_host'],
                                            description, 'Metadata Crawling'])

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

        addr = urlparse.urlparse(self.__access_log)  # Se obtiene el nombre del fichero de eventos
        filename = "data/mc-" + addr.hostname + '-' + self.person + "-events.log"
        line_parser = apache_log_parser.make_parser(self.__access_log_format.decode('string_escape'))

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
                    if not ip_list.count([ip, False]):
                        ip_list.append([ip, False])

                linea = f.readline()

        return ip_list
