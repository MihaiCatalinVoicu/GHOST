//! A small ISO-BMFF box-tree editor for building fMP4 test inputs from the goldens: parse a box
//! sequence into nodes, change values or children, serialise with recomputed sizes.
#![allow(dead_code)]

/// A box: a leaf with its body, or a container with a fixed prefix (stsd's entry count, a sample
/// entry's fields) and children.
#[derive(Clone, Debug)]
pub enum Node {
    Leaf {
        typ: [u8; 4],
        body: Vec<u8>,
    },
    Parent {
        typ: [u8; 4],
        prefix: Vec<u8>,
        kids: Vec<Node>,
    },
}

fn prefix_len(typ: &[u8; 4]) -> Option<usize> {
    match typ {
        b"moov" | b"trak" | b"mdia" | b"minf" | b"dinf" | b"stbl" | b"mvex" | b"moof" | b"traf"
        | b"mfra" | b"edts" => Some(0),
        b"stsd" => Some(8),
        b"avc1" => Some(78),
        b"mp4a" => Some(28),
        _ => None,
    }
}

/// Parses the boxes of `data`.
pub fn parse(data: &[u8]) -> Vec<Node> {
    let mut out = Vec::new();
    let mut o = 0;
    while o + 8 <= data.len() {
        let size = u32::from_be_bytes(data[o..o + 4].try_into().unwrap()) as usize;
        let typ: [u8; 4] = data[o + 4..o + 8].try_into().unwrap();
        let body = &data[o + 8..o + size];
        out.push(match prefix_len(&typ) {
            Some(p) => Node::Parent {
                typ,
                prefix: body[..p].to_vec(),
                kids: parse(&body[p..]),
            },
            None => Node::Leaf {
                typ,
                body: body.to_vec(),
            },
        });
        o += size;
    }
    out
}

/// Serialises nodes with their sizes.
pub fn serialize(nodes: &[Node]) -> Vec<u8> {
    let mut out = Vec::new();
    for n in nodes {
        let (typ, body) = match n {
            Node::Leaf { typ, body } => (*typ, body.clone()),
            Node::Parent { typ, prefix, kids } => {
                let mut b = prefix.clone();
                b.extend(serialize(kids));
                (*typ, b)
            }
        };
        out.extend_from_slice(&((body.len() + 8) as u32).to_be_bytes());
        out.extend_from_slice(&typ);
        out.extend(body);
    }
    out
}

impl Node {
    pub fn typ(&self) -> [u8; 4] {
        match self {
            Node::Leaf { typ, .. } | Node::Parent { typ, .. } => *typ,
        }
    }

    pub fn kids_mut(&mut self) -> &mut Vec<Node> {
        match self {
            Node::Parent { kids, .. } => kids,
            Node::Leaf { .. } => panic!("a leaf has no children"),
        }
    }

    pub fn body_mut(&mut self) -> &mut Vec<u8> {
        match self {
            Node::Leaf { body, .. } => body,
            Node::Parent { prefix, .. } => prefix,
        }
    }
}

/// The node at `path` (`"trak#1"` is the second `trak` of its parent).
pub fn at<'a>(nodes: &'a mut [Node], path: &[&str]) -> &'a mut Node {
    let (first, rest) = path.split_first().expect("a path");
    let (name, index) = match first.split_once('#') {
        Some((n, i)) => (n, i.parse::<usize>().unwrap()),
        None => (*first, 0),
    };
    let node = nodes
        .iter_mut()
        .filter(|n| n.typ() == name.as_bytes())
        .nth(index)
        .unwrap_or_else(|| panic!("no {first}"));
    if rest.is_empty() {
        node
    } else {
        at(node.kids_mut(), rest)
    }
}

/// A leaf box's bytes.
pub fn leaf(typ: &[u8; 4], body: &[u8]) -> Node {
    Node::Leaf {
        typ: *typ,
        body: body.to_vec(),
    }
}
