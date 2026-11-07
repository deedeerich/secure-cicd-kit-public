#!/usr/bin/env python3
"""The seeded PHP corpus behind sast-semgrep's PHP range (lane L-PHP; D-VF-4, ledger V-02).

WHY THIS EXISTS

    scanner-registry.yaml `version_support` sast-semgrep/php was UNVERIFIED: Semgrep carries its own
    PHP parser and does not publish which PHP releases it reads. An UNVERIFIED range is never
    capable (KDEC-010), so every PHP target was a VERSION_GAP and every PHP repository's Semgrep
    PASS was capped at PARTIAL. A range is proven the way the Terraform corpus proved checkov's
    (tests/corpora/terraform_corpus.py): a file written in the target release's syntax, holding a
    seed the scanner is known to report, and the question is whether the finding comes back AND
    the parser says it read the file.

WHAT A FAMILY IS

    One PHP release line that added syntax. Each family's file uses that release's constructs and
    then holds the same seed (request input concatenated into `system()`), AFTER the constructs, so
    a parser that gives up at the construct never reaches it. Releases that added no syntax are
    claimed through their neighbours.

    THE FAMILIES THEMSELVES ARE MEASURED, not only Semgrep on them (2026-10-21): every family's file
    passes `php -l` under the official php:<family>-cli image and FAILS it under the release before
    (php:5.6-cli .. php:8.4-cli), and the control fails it under 8.4. The 8.5 family (lane L-SG)
    passes under php:8.5-cli (8.5.12) and fails under php:8.4-cli (8.4.27), and each of its three
    constructs fails 8.4 on its own; the control fails 8.5 too. So "this file is PHP <v>
    syntax that PHP <v-1> cannot read" is a fact about PHP, and a Semgrep that cannot read it has
    met that release's syntax, not a typo in the corpus.

    The CONTROL is a deliberately unparseable file holding the same seed. Semgrep must REPORT an
    error for it; a Semgrep that is silent about an unreadable file cannot tell "could not read"
    from "clean", and the probe refuses to write a range (exit 2).

THE RULE
    A local rule, written beside the corpus when a probe runs, matching the seed's sink. No registry
    ruleset is fetched: the question is whether the PARSER reads the file, and a registry rule that
    changes upstream must not move the measurement.

TEST-ONLY INPUT (KDEC-011)
    The corpus is DATA in this module, written to a temporary directory only when a probe runs. No
    .php file is committed by it, so no consumer's scan, and no export of this kit, meets a seed
    as a finding. tests/prove_php_corpus.py holds that to be true.
"""
import os

SEED = '''
// corpus seed: request input reaches a shell command (deliberate)
system("ping -c 1 " . $_GET["host"]);
'''

RULE_ID = 'corpus-php-seed'
RULE = '''rules:
  - id: corpus-php-seed
    languages: [php]
    severity: ERROR
    message: corpus seed reached system()
    pattern: system(...)
'''

CONTROL = 'control-unparseable'

# (family, construct, body). Ordered oldest first; the probe measures contiguously from the first.
FAMILIES = [
    ('5.6', 'variadics and argument unpacking; ** ; use function; constant scalar expressions', r'''
namespace Corpus56;

use function strlen as len;

const TWO = 1 + 1;

function total(...$numbers) {
    return array_sum($numbers);
}

$args = [1, 2, 3];
$sum = total(...$args);
$power = 2 ** 8;
$n = len("abc");
'''),
    ('7.0', 'scalar and return type declarations; ?? ; <=> ; anonymous classes; group use; yield from', r'''
namespace Corpus70;

use Corpus70\Sub\{Alpha, Beta};

function add(int $a, int $b): int {
    return $a + $b;
}

function gen(): \Generator {
    yield 1;
    yield from [2, 3];
}

$name = $_GET["name"] ?? "anonymous";
$cmp = 1 <=> 2;
$obj = new class {
    public function hello(): string { return "hi"; }
};
'''),
    ('7.1', 'nullable types; void; iterable; symmetric array destructuring with keys; multi-catch; constant visibility', r'''
namespace Corpus71;

class Box {
    private const SECRET = 1;
    public function maybe(?string $s): ?string { return $s; }
    public function nothing(): void {}
    public function each(iterable $it): void {}
}

[$a, $b] = [1, 2];
["x" => $x, "y" => $y] = ["x" => 1, "y" => 2];

try {
    throw new \RuntimeException("x");
} catch (\RuntimeException | \LogicException $e) {
    $msg = $e->getMessage();
}
'''),
    ('7.2', 'the object type; abstract method overriding; trailing comma in grouped namespaces', r'''
namespace Corpus72;

use Corpus72\Parts\{One, Two,};

abstract class Base {
    abstract public function make(object $o): object;
}

abstract class Child extends Base {
    abstract public function make(object $o): object;
}

function take(object $o): object {
    return $o;
}
'''),
    ('7.3', 'flexible heredoc and nowdoc; trailing comma in calls; reference assignment in list()', r'''
namespace Corpus73;

$text = <<<EOT
    indented body
      kept relative
    EOT;

$joined = implode(",", [
    "a",
    "b",
],);

$arr = [1, 2];
[$first, &$second] = $arr;
'''),
    ('7.4', 'typed properties; arrow functions; ??= ; spread in arrays; numeric literal separator', r'''
namespace Corpus74;

class User {
    public int $id = 0;
    public ?string $name = null;
    private array $roles = [];
}

$double = fn(int $x): int => $x * 2;
$config = [];
$config["mode"] ??= "safe";
$merged = [...[1, 2], ...[3]];
$million = 1_000_000;
'''),
    ('8.0', 'named arguments; match; nullsafe; union types; constructor promotion; attributes; throw expression', r'''
namespace Corpus80;

#[\Attribute]
class Route {
    public function __construct(public string $path = "/", private int|float $weight = 1) {}
}

#[Route(path: "/x")]
class Controller {
    public function handler(int|string $id, mixed $extra = null): static|null {
        return null;
    }
}

$label = match (true) {
    1 > 2 => "no",
    default => "yes",
};
$len = $maybe?->name?->length;
$v = $input ?? throw new \InvalidArgumentException("missing");
$s = str_pad(string: "x", length: 5, pad_string: "-");
'''),
    ('8.1', 'enums; readonly properties; never; first-class callables; new in initialisers; intersection types; 0o octal', r'''
namespace Corpus81;

enum Suit: string {
    case Hearts = "H";
    case Spades = "S";
    public function label(): string { return ucfirst($this->name); }
}

class Service {
    public function __construct(
        public readonly int $id,
        private Logger $logger = new Logger(),
    ) {}
    public function stop(): never { exit(1); }
    public function both(\Countable&\Traversable $x): void {}
}

class Logger {}

$strlen = strlen(...);
$mode = 0o755;
$all = [...["a" => 1], ...["b" => 2]];
'''),
    ('8.2', 'readonly classes; DNF types; true, false and null as standalone types; constants in traits', r'''
namespace Corpus82;

trait HasVersion {
    public const VERSION = 2;
}

readonly class Point {
    public function __construct(public int $x, public int $y) {}
}

class Flags {
    use HasVersion;
    public function yes(): true { return true; }
    public function no(): false { return false; }
    public function none(): null { return null; }
    public function dnf((\Countable&\Traversable)|null $x): void {}
}
'''),
    ('8.3', 'typed class constants; dynamic class constant fetch; the Override attribute', r'''
namespace Corpus83;

interface HasName {
    const string NAME = "corpus";
    public function name(): string;
}

class Named implements HasName {
    const string LABEL = "named";
    #[\Override]
    public function name(): string { return self::NAME; }
}

$which = "LABEL";
$value = Named::{$which};
'''),
    ('8.4', 'property hooks; asymmetric visibility; new without parentheses before member access', r'''
namespace Corpus84;

class Account {
    public private(set) int $balance = 0;

    public string $owner {
        set(string $value) {
            $this->owner = strtolower($value);
        }
        get => ucfirst($this->owner);
    }
}

$len = new \ArrayObject([1, 2])->count();
'''),
    # 8.5 (lane L-SG, 2026-10-21; php.net migration85.new-features): the pipe operator, the (void)
    # cast, and constructor promotion of final properties.
    ('8.5', 'the pipe operator; the (void) cast; final promoted properties', r'''
namespace Corpus85;

class Box {
    public function __construct(final public int $size) {}
}

$length = "corpus" |> strtoupper(...) |> strlen(...);
(void) strlen("ignored");
'''),
]

# A class body left open and an expression cut off: no PHP parser can read this file.
control_body = '''
class Broken {
    public function oops( {
        $x = [1, 2
'''


def family_names():
    return [f for f, _c, _b in FAMILIES]


def source(family):
    """-> the .php text for one family (or the control). The seed comes LAST."""
    if family == CONTROL:
        return '<?php\n// corpus control: unparseable on purpose\n' + control_body + SEED
    for f, construct, body in FAMILIES:
        if f == family:
            return '<?php\n// corpus family %s: %s\n%s%s' % (f, construct, body, SEED)
    raise KeyError(family)


def file_name(family):
    return 'php_' + family.replace('.', '_').replace('-', '_') + '.php'


def materialise(base, families=None):
    """Write one directory per family (and the control) under `base`, each holding one file, and
    the local rule beside them. -> ({family: file path}, rule path)."""
    out = {}
    for f in list(families or family_names()) + [CONTROL]:
        d = os.path.join(base, 'php-' + f.replace('.', '_'))
        os.makedirs(d, exist_ok=True)
        p = os.path.join(d, file_name(f))
        with open(p, 'w', encoding='utf-8', newline='\n') as fh:
            fh.write(source(f))
        out[f] = p
    rule = os.path.join(base, 'corpus-rule.yml')
    with open(rule, 'w', encoding='utf-8', newline='\n') as fh:
        fh.write(RULE)
    return out, rule
