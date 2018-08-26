<?php

namespace Codecasts\Auth\JWT\Console;

use Illuminate\Console\Command;
use Illuminate\Console\ConfirmableTrait;
use Symfony\Component\Console\Helper\FormatterHelper;

/**
 * Class GenerateKey.
 *
 * Command that helps generating a strong key to be used as HMAC-SHA256 key.
 */
class KeyGenerateCommand extends Command
{
    use ConfirmableTrait;

    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'jwt:generate
            {--show : Display the key instead of modifying files}
            {--force : Force the operation to run when in production}';

    /**
     * Make it 5.4 compatible.
     */
    public function fire()
    {
        $this->handle();
    }

    /**
     * Execute the command that will generate and print a key.
     */
    public function handle()
    {
        // call the action to generate a new key.
        $key = $this->generateRandomKey();

        if ($this->option('show')) {
            // print the success block.
            $this->printBlock([
                'JWT Key Generated!',
                'Please Update your .env file manually with the following key:',
            ], 'bg=green;fg=black', true);

            // print the key block.
            return $this->printBlock([
                "JWT_SECRET={$key}",
            ], 'bg=yellow;fg=black');
        }

        // Next, we will replace the application key in the environment file so it is
        // automatically setup for this developer. This key gets generated using a
        // secure random byte generator and is later base64 encoded for storage.
        if (!$this->setKeyInEnvironmentFile($key)) {
            return;
        }

        $this->laravel['config']['jwt.secret'] = $key;

        // print the key block.
        $this->printBlock([
            "JWT_SECRET={$key}",
        ], 'bg=yellow;fg=black');
    }

    /**
     * Set the application key in the environment file.
     *
     * @param string $key
     *
     * @return bool
     */
    protected function setKeyInEnvironmentFile($key)
    {
        $currentKey = $this->laravel['config']['jwt.secret'];

        if (0 !== strlen($currentKey) && (!$this->confirmToProceed())) {
            return false;
        }

        $this->writeNewEnvironmentFileWith($key);

        return true;
    }

    /**
     * Write a new environment file with the given key.
     *
     * @param string $key
     */
    protected function writeNewEnvironmentFileWith($key)
    {
        file_put_contents($this->laravel->environmentFilePath(), preg_replace(
                $this->keyReplacementPattern(),
                'JWT_SECRET='.$key,
                file_get_contents($this->laravel->environmentFilePath())
            ));
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

    /**
     * Get a regex pattern that will match env APP_KEY with any random key.
     *
     * @return string
     */
    protected function keyReplacementPattern()
    {
        $escaped = preg_quote('='.$this->laravel['config']['jwt.secret'], '/');

        return "/^JWT_SECRET{$escaped}/m";
    }
}
