<?php

namespace Codecasts\Auth\JWT\Console;

use Illuminate\Console\Command;
use Symfony\Component\Console\Helper\FormatterHelper;

/**
 * Class GenerateKey.
 *
 * Command that helps generating a strong key to be used as HMAC-SHA256 key.
 */
class KeyGenerateCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'jwt:generate';

    /**
     * Make it 5.4 compatible.
     */
    public function fire()
    {
        $this->handle();
    }

    /**
     * Execute the command that will generate and print a key.
     *
     * @return void
     */
    public function handle()
    {
        // call the action to generate a new key.
        $key = $this->generateRandomKey();

        // print the success block.
        $this->printBlock([
            'JWT Key Generated!',
            'Please Update your .env file manually with the following key:',
        ], 'bg=green;fg=black', true);

        // print the key block.
        $this->printBlock([
            "JWT_SECRET={$key}",
        ], 'bg=yellow;fg=black');
    }

    /**
     * Generates a random, 32 bytes long, base64 encoded key.
     *
     * @return string
     */
    protected function generateRandomKey()
    {
        return 'base64:'.base64_encode(random_bytes(32));
    }

    /**
     * Prints a text block into console output.
     *
     * @param array $lines
     * @param $style
     * @param bool $firstBlock
     */
    protected function printBlock(array $lines, $style, $firstBlock = false)
    {
        /** @var FormatterHelper $formatter */
        $formatter = $this->getHelper('formatter');

        // just to satisfy my obsessive needs.
        if ($firstBlock) {
            // prints an empty line at the begging of output.
            $this->line('');
        }

        // merge argument lines with an empty line before and after.
        $spacedLines = array_merge([''], array_merge($lines, ['']));
        // generate a text block.
        $block = $formatter->formatBlock($spacedLines, $style);

        // print it.
        $this->line($block);

        // empty ending line.
        $this->line('');
    }
}
