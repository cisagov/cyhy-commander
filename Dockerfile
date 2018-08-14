FROM dhub.ncats.dhs.gov:5001/cyhy-core
MAINTAINER Mark Feldhousen <mark.feldhousen@hq.dhs.gov>
ENV CYHY_COMMANDER_SRC="/usr/src/cyhy-commander"

USER root
WORKDIR ${CYHY_COMMANDER_SRC}

COPY . ${CYHY_COMMANDER_SRC}
RUN pip install --no-cache-dir -r requirements.txt

USER cyhy
WORKDIR ${CYHY_HOME}
CMD ["cyhy-commander", "--debug", "--stdout-log", "commander"]
