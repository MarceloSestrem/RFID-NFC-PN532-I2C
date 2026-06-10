/**
 * Blocos para controle do Módulo RFID/NFC PN532 via I2C
 */
//% color="#27ae60" icon="\uf2bb" block="RFID PN532"
namespace pn532 {
    const PN532_I2C_ADDRESS = 0x24;

    // Comandos básicos do PN532
    const PN532_COMMAND_GETFIRMWAREVERSION = 0x02;
    const PN532_COMMAND_SAMCONFIGURATION = 0x14;
    const PN532_COMMAND_INLISTPASSIVETARGET = 0x4A;

    /**
     * Inicializa o PN532 e o configura para leitura de cartões (Modo SAM).
     */
    //% block="inicializar PN532"
    //% weight=100
    export function init(): void {
        // 1. Acorda o módulo enviando um comando básico de configuração (SAM Configuration)
        let buf = pins.createBuffer(8);
        buf.setNumber(NumberFormat.UInt8LE, 0, 0x00); // Preâmbulo
        buf.setNumber(NumberFormat.UInt8LE, 1, 0x00);
        buf.setNumber(NumberFormat.UInt8LE, 2, 0xFF); // Início do pacote
        buf.setNumber(NumberFormat.UInt8LE, 3, 0x05); // Tamanho do pacote
        buf.setNumber(NumberFormat.UInt8LE, 4, 0xFB); // Checksum do tamanho
        buf.setNumber(NumberFormat.UInt8LE, 5, 0xD4); // Direção (Host para PN532)
        buf.setNumber(NumberFormat.UInt8LE, 6, PN532_COMMAND_SAMCONFIGURATION);
        buf.setNumber(NumberFormat.UInt8LE, 7, 0x01); // Modo Normal

        pins.i2cWriteBuffer(PN532_I2C_ADDRESS, buf);
        basic.pause(100);
    }

    /**
     * Verifica se há algum cartão ou chaveiro de 13.56 Mhz próximo ao leitor.
     */
    //% block="cartão ou chaveiro detectado?"
    //% weight=90
    export function isCardPresent(): boolean {
        let command = pins.createBuffer(9);
        // Comando InListPassiveTarget para buscar 1 cartão ISO14443A (Mifare)
        command.setNumber(NumberFormat.UInt8LE, 0, 0x00);
        command.setNumber(NumberFormat.UInt8LE, 1, 0x00);
        command.setNumber(NumberFormat.UInt8LE, 2, 0xFF);
        command.setNumber(NumberFormat.UInt8LE, 3, 0x04);
        command.setNumber(NumberFormat.UInt8LE, 4, 0xFC);
        command.setNumber(NumberFormat.UInt8LE, 5, 0xD4);
        command.setNumber(NumberFormat.UInt8LE, 6, PN532_COMMAND_INLISTPASSIVETARGET);
        command.setNumber(NumberFormat.UInt8LE, 7, 0x01); // Quantidade máxima de alvos
        command.setNumber(NumberFormat.UInt8LE, 8, 0x00); // Baud rate (106 kbps)

        pins.i2cWriteBuffer(PN532_I2C_ADDRESS, command);
        basic.pause(60);

        // Ler a resposta do PN532
        let response = pins.i2cReadBuffer(PN532_I2C_ADDRESS, 20);

        // Na resposta do PN532, se ele encontrar uma tag, o byte de status confirma o sucesso
        // Verificação simplificada: checa se retornou dados válidos de tag
        if (response.getNumber(NumberFormat.UInt8LE, 7) == 0x4B) {
            return true;
        }
        return false;
    }

    /**
     * Retorna o UID (Identificador Único) do cartão detectado como texto.
     */
    //% block="ler UID do cartão"
    //% weight=80
    export function readUID(): string {
        let response = pins.i2cReadBuffer(PN532_I2C_ADDRESS, 20);

        // O UID Mifare padrão geralmente começa a partir do byte 14 na resposta do InListPassiveTarget
        let uidLength = response.getNumber(NumberFormat.UInt8LE, 12);
        let uidString = "";

        if (uidLength > 0 && uidLength <= 7) {
            for (let i = 0; i < uidLength; i++) {
                let byte = response.getNumber(NumberFormat.UInt8LE, 13 + i);
                uidString += byte.toString() + " ";
            }
        }

        return uidString.trim();
    }
}